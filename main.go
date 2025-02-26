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
	allowedDirs []string
	server      *server.MCPServer
	cache       map[string]*CacheEntry
	cacheMutex  sync.RWMutex
}

const (
	cacheTTL        = 5 * time.Minute  // Cache entries expire after 5 minutes
	maxCacheSize    = 50 * 1024 * 1024 // 50MB max cache size
	compressMinSize = 1024 * 1024      // Compress files larger than 1MB
)

func (s *FilesystemServer) getCached(path string) ([]byte, bool) {
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
	if len(content) > maxCacheSize {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	// Clean up old entries if cache is too large
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
	for _, dir := range allowedDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", dir, err)
		}

		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("failed to access directory %s: %w", abs, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("path is not a directory: %s", abs)
		}

		normalized = append(normalized, filepath.Clean(strings.ToLower(abs)))
	}

	s := &FilesystemServer{
		allowedDirs: normalized,
		server: server.NewMCPServer(
			"filesystem-server",
			"0.4.0",
			server.WithToolCapabilities(true),
		),
		cache: make(map[string]*CacheEntry),
	}

	// Register tools
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
			},
		},
	}, s.handleReadFile)

	s.server.AddTool(mcp.Tool{
		Name:        "batch_read",
		Description: "Read multiple files",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"paths": map[string]interface{}{
					"type":        "array",
					"description": "File paths",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}, s.handleBatchRead)

	s.server.AddTool(mcp.Tool{
		Name:        "write",
		Description: "Write file",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "File path",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Content",
				},
			},
		},
	}, s.handleWriteFile)

	s.server.AddTool(mcp.Tool{
		Name:        "batch_write",
		Description: "Write multiple files",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"files": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"path": map[string]interface{}{
								"type": "string",
							},
							"content": map[string]interface{}{
								"type": "string",
							},
						},
					},
				},
			},
		},
	}, s.handleBatchWrite)

	s.server.AddTool(mcp.Tool{
		Name:        "ls",
		Description: "List dir",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Dir path",
				},
			},
		},
	}, s.handleListDirectory)

	s.server.AddTool(mcp.Tool{
		Name:        "info",
		Description: "File info",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "File path",
				},
			},
		},
	}, s.handleGetFileInfo)

	s.server.AddTool(mcp.Tool{
		Name:        "find",
		Description: "Find files",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Start path",
				},
				"pattern": map[string]interface{}{
					"type":        "string",
					"description": "Pattern",
				},
			},
		},
	}, s.handleSearchFiles)

	s.server.AddTool(mcp.Tool{
		Name:        "dirs",
		Description: "Allowed dirs",
		InputSchema: mcp.ToolInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
		},
	}, s.handleListAllowedDirectories)

	return s, nil
}

func (s *FilesystemServer) validatePath(requestedPath string) (string, error) {
	abs, err := filepath.Abs(requestedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	normalized := filepath.Clean(strings.ToLower(abs))

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
				normalizedParent := filepath.Clean(strings.ToLower(realParent))
				for _, dir := range s.allowedDirs {
					if strings.HasPrefix(normalizedParent, dir) {
						return abs, nil
					}
				}
				return "", fmt.Errorf("access denied - parent dir")
			}
			normalizedReal := filepath.Clean(strings.ToLower(realPath))
			for _, dir := range s.allowedDirs {
				if strings.HasPrefix(normalizedReal, dir) {
					return realPath, nil
				}
			}
			return "", fmt.Errorf("access denied - symlink")
		}
	}
	return "", fmt.Errorf("access denied")
}

func (s *FilesystemServer) getFileStats(path string) (FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}

	return FileInfo{
		Size:     info.Size(),
		Modified: info.ModTime(),
		Mode:     info.Mode(),
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

	// Check cache first
	if content, ok := s.getCached(validPath); ok {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: string(content)}},
		}, nil
	}

	content, err := os.ReadFile(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	// Store in cache
	s.setCache(validPath, content)

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: string(content)}},
	}, nil
}

func (s *FilesystemServer) handleBatchRead(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	paths, ok := arguments["paths"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("paths required")
	}

	var wg sync.WaitGroup
	results := make([]string, len(paths))
	errors := make([]error, len(paths))

	for i, p := range paths {
		path, ok := p.(string)
		if !ok {
			return nil, fmt.Errorf("invalid path at index %d", i)
		}

		wg.Add(1)
		go func(idx int, filePath string) {
			defer wg.Done()
			validPath, err := s.validatePath(filePath)
			if err != nil {
				errors[idx] = err
				return
			}

			if content, ok := s.getCached(validPath); ok {
				results[idx] = string(content)
				return
			}

			content, err := os.ReadFile(validPath)
			if err != nil {
				errors[idx] = err
				return
			}

			s.setCache(validPath, content)
			results[idx] = string(content)
		}(i, path)
	}

	wg.Wait()

	// Combine results
	var result strings.Builder
	for i, content := range results {
		if errors[i] != nil {
			fmt.Fprintf(&result, "[Error reading %s: %v]\n", paths[i], errors[i])
		} else {
			fmt.Fprintf(&result, "[File: %s]\n%s\n", paths[i], content)
		}
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: result.String()}},
	}, nil
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

	// Invalidate cache
	s.cacheMutex.Lock()
	delete(s.cache, validPath)
	s.cacheMutex.Unlock()

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: "ok"}},
	}, nil
}

func (s *FilesystemServer) handleBatchWrite(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	files, ok := arguments["files"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("files required")
	}

	type writeOp struct {
		path    string
		content string
		err     error
	}

	results := make([]writeOp, len(files))
	var wg sync.WaitGroup

	for i, f := range files {
		file, ok := f.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid file at index %d", i)
		}

		path, ok := file["path"].(string)
		if !ok {
			return nil, fmt.Errorf("path required for file at index %d", i)
		}
		content, ok := file["content"].(string)
		if !ok {
			return nil, fmt.Errorf("content required for file at index %d", i)
		}

		results[i] = writeOp{path: path, content: content}
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()
			validPath, err := s.validatePath(results[idx].path)
			if err != nil {
				results[idx].err = err
				return
			}

			err = s.atomicWrite(validPath, []byte(results[idx].content), 0644)
			if err != nil {
				results[idx].err = err
				return
			}

			s.cacheMutex.Lock()
			delete(s.cache, validPath)
			s.cacheMutex.Unlock()
		}(i)
	}

	wg.Wait()

	var result strings.Builder
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(&result, "[Error writing %s: %v]\n", r.path, r.err)
		} else {
			fmt.Fprintf(&result, "[OK: %s]\n", r.path)
		}
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: result.String()}},
	}, nil
}

func (s *FilesystemServer) handleListDirectory(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path required")
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

	var result strings.Builder
	for _, entry := range entries {
		fmt.Fprintln(&result, entry.Name())
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{Type: "text", Text: result.String()}},
	}, nil
}

func (s *FilesystemServer) handleSearchFiles(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path required")
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
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Use worker pool for large directories
	const maxWorkers = 4
	paths := make(chan string, 100)
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if strings.Contains(strings.ToLower(info.Name()), strings.ToLower(pattern)) {
					mutex.Lock()
					matches = append(matches, path)
					mutex.Unlock()
				}
			}
		}()
	}

	err = filepath.Walk(validPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		paths <- path
		return nil
	})

	close(paths)
	wg.Wait()

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

func (s *FilesystemServer) handleGetFileInfo(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path required")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	info, err := s.getFileStats(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{mcp.TextContent{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{
			Type: "text",
			Text: fmt.Sprintf("%s %d %s", info.Mode, info.Size, info.Modified.Format(time.RFC3339)),
		}},
	}, nil
}

func (s *FilesystemServer) handleListAllowedDirectories(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []interface{}{mcp.TextContent{
			Type: "text",
			Text: strings.Join(s.allowedDirs, "\n"),
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
