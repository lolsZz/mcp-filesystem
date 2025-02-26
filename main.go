package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type FileInfo struct {
	Size     int64       `json:"size"`
	Modified time.Time   `json:"modified"`
	Mode     os.FileMode `json:"mode"`
}

type CacheEntry struct {
	Content  []byte
	ModTime  time.Time
	ExpireAt time.Time
}

type FilesystemServer struct {
	allowedDirs  []string
	originalDirs []string
	server       *server.MCPServer
	cache        map[string]*CacheEntry
	cacheMutex   sync.RWMutex
	cacheEnabled bool
}

const (
	cacheTTL        = 5 * time.Minute
	maxCacheSize    = 50 * 1024 * 1024
	compressMinSize = 1024 * 1024
)

func (s *FilesystemServer) getCached(path string) ([]byte, bool) {
	if !s.cacheEnabled {
		return nil, false
	}

	s.cacheMutex.RLock()
	entry, exists := s.cache[path]
	s.cacheMutex.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpireAt) {
		s.cacheMutex.Lock()
		delete(s.cache, path)
		s.cacheMutex.Unlock()
		return nil, false
	}

	info, err := os.Stat(path)
	if err != nil || info.ModTime() != entry.ModTime {
		s.cacheMutex.Lock()
		delete(s.cache, path)
		s.cacheMutex.Unlock()
		return nil, false
	}

	return entry.Content, true
}

func (s *FilesystemServer) setCache(path string, content []byte) {
	if !s.cacheEnabled {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	var totalSize int64
	for _, entry := range s.cache {
		totalSize += int64(len(entry.Content))
	}
	if totalSize+int64(len(content)) > maxCacheSize {
		s.cache = make(map[string]*CacheEntry)
	}

	s.cache[path] = &CacheEntry{
		Content:  content,
		ModTime:  info.ModTime(),
		ExpireAt: time.Now().Add(cacheTTL),
	}
}

func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressData(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

func (s *FilesystemServer) atomicWrite(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if len(content) > compressMinSize {
		compressed, err := compressData(content)
		if err == nil && len(compressed) < len(content) {
			content = compressed
		}
	}

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	success = true
	return nil
}

func NewFilesystemServer(allowedDirs []string) (*FilesystemServer, error) {
	normalized := make([]string, 0, len(allowedDirs))
	originals := make([]string, 0, len(allowedDirs))

	for _, dir := range allowedDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", dir, err)
		}

		clean := filepath.Clean(abs)
		info, err := os.Stat(clean)
		if err != nil {
			return nil, fmt.Errorf("failed to access directory %s: %w", clean, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("path is not a directory: %s", clean)
		}

		normalized = append(normalized, strings.ToLower(clean))
		originals = append(originals, clean)
	}

	if len(originals) > 0 {
		if err := os.Chdir(originals[0]); err != nil {
			return nil, fmt.Errorf("failed to set working directory: %w", err)
		}
	}

	s := &FilesystemServer{
		allowedDirs:  normalized,
		originalDirs: originals,
		server: server.NewMCPServer(
			"better-filesystem-mcp-server",
			"0.4.1",
			server.WithToolCapabilities(true),
		),
		cache:        make(map[string]*CacheEntry),
		cacheEnabled: true,
	}

	s.server.AddTool(mcp.Tool{
		Name:        "cache",
		Description: "Enable/disable file cache",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable or disable cache",
				},
			},
		},
	}, s.handleCacheControl)

	s.server.AddTool(mcp.Tool{
		Name:        "read",
		Description: "Read file",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "File path",
				},
				"nocache": map[string]interface{}{
					"type":        "boolean",
					"description": "Skip cache for this read",
				},
			},
		},
	}, s.handleReadFile)

	s.server.AddTool(mcp.Tool{
		Name:        "ls",
		Description: "List directory contents",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Directory path",
				},
			},
		},
	}, s.handleListDirectory)

	s.server.AddTool(mcp.Tool{
		Name:        "find",
		Description: "Find files by pattern",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Base directory for search",
				},
				"pattern": map[string]interface{}{
					"type":        "string",
					"description": "Search pattern",
				},
			},
		},
	}, s.handleFind)

	s.server.AddTool(mcp.Tool{
		Name:        "dirs",
		Description: "List allowed directories",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
		},
	}, s.handleDirs)

	s.server.AddTool(mcp.Tool{
		Name:        "info",
		Description: "Get file information",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "File path",
				},
			},
		},
	}, s.handleFileInfo)

	s.server.AddTool(mcp.Tool{
		Name:        "write",
		Description: "Write file with atomic operations",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "File path",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "File content",
				},
			},
		},
	}, s.handleWriteFile)

	return s, nil
}

func (s *FilesystemServer) validatePath(requestedPath string) (string, error) {
	abs, err := filepath.Abs(requestedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	normalized := strings.ToLower(filepath.Clean(abs))

	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(normalized, dir) {
			realPath, err := filepath.EvalSymlinks(abs)
			if err != nil {
				if !os.IsNotExist(err) {
					return "", err
				}
				parent := filepath.Dir(abs)
				realParent, err := filepath.EvalSymlinks(parent)
				if err != nil {
					return "", fmt.Errorf("parent directory does not exist: %s", parent)
				}
				normalizedParent := strings.ToLower(filepath.Clean(realParent))
				for j, allowedDir := range s.allowedDirs {
					if strings.HasPrefix(normalizedParent, allowedDir) {
						return filepath.Join(s.originalDirs[j], filepath.Base(abs)), nil
					}
				}
				return "", fmt.Errorf("access denied - parent dir")
			}
			normalizedReal := strings.ToLower(filepath.Clean(realPath))
			for j, allowedDir := range s.allowedDirs {
				if strings.HasPrefix(normalizedReal, allowedDir) {
					return s.originalDirs[j] + strings.TrimPrefix(realPath, s.originalDirs[j]), nil
				}
			}
			return "", fmt.Errorf("access denied - symlink")
		}
	}
	return "", fmt.Errorf("access denied")
}

func (s *FilesystemServer) handleWriteFile(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path required")
	}
	content, ok := arguments["content"].(string)
	if !ok {
		return nil, fmt.Errorf("content required")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	if err := s.atomicWrite(validPath, []byte(content), 0644); err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: "File written successfully"}},
	}, nil
}

func (s *FilesystemServer) handleReadFile(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path required")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	skipCache := false
	if nc, ok := arguments["nocache"].(bool); ok {
		skipCache = nc
	}

	if !skipCache {
		if content, ok := s.getCached(validPath); ok {
			return &mcp.CallToolResult{
				Content: []interface{}{mcp.TextContent{Type: "text", Text: string(content)}},
			}, nil
		}
	}

	content, err := os.ReadFile(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	if !skipCache {
		s.setCache(validPath, content)
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: string(content)}},
	}, nil
}

func (s *FilesystemServer) handleListDirectory(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		path = "."
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	var listing strings.Builder
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		listing.WriteString(fmt.Sprintf("%s %8d %s\n", info.Mode(), info.Size(), entry.Name()))
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: listing.String()}},
	}, nil
}

func (s *FilesystemServer) handleFind(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		path = "."
	}

	pattern, ok := arguments["pattern"].(string)
	if !ok {
		return nil, fmt.Errorf("pattern required")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	var matches []string
	err = filepath.Walk(validPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if matched, _ := filepath.Match(pattern, info.Name()); matched {
			matches = append(matches, path)
		}
		return nil
	})

	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: strings.Join(matches, "\n")}},
	}, nil
}

func (s *FilesystemServer) handleDirs(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	var result strings.Builder
	for _, dir := range s.originalDirs {
		result.WriteString(dir)
		result.WriteString("\n")
	}
	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: result.String()}},
	}, nil
}

func (s *FilesystemServer) handleFileInfo(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path required")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{
			Type: "text",
			Text: fmt.Sprintf("%s %d %s", info.Mode(), info.Size(), info.ModTime()),
		}},
	}, nil
}

func (s *FilesystemServer) handleCacheControl(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	enabled, ok := arguments["enabled"].(bool)
	if !ok {
		return nil, fmt.Errorf("enabled must be a boolean")
	}

	s.cacheEnabled = enabled
	if !enabled {
		s.cacheMutex.Lock()
		s.cache = make(map[string]*CacheEntry)
		s.cacheMutex.Unlock()
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{
			Type: "text",
			Text: fmt.Sprintf("Cache %s", map[bool]string{true: "enabled", false: "disabled"}[enabled]),
		}},
	}, nil
}

func (s *FilesystemServer) Serve() error {
	return server.ServeStdio(s.server)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <allowed-dir> [more-dirs...]\n", os.Args[0])
		os.Exit(1)
	}

	fs, err := NewFilesystemServer(os.Args[1:])
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if err := fs.Serve(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
