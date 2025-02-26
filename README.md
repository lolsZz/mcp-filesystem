# Filesystem MCP Server

High-performance filesystem operations server with atomic writes, caching, and parallel processing capabilities.

## Features

- Atomic file operations
- In-memory caching with TTL
- Automatic compression
- Concurrent batch operations
- Path security validation
- Configurable allowed directories

## Installation

```bash
cd mcp-filesystem
go build -o build/filesystem-mcp
```

## Configuration

Add to Cline MCP settings (`cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/path/to/filesystem-mcp",
      "args": ["/allowed/directory/path", "/another/allowed/path"],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Tools Reference

### File Operations

#### read

Reads file contents with caching support.

```json
{
  "path": "/path/to/file",
  "nocache": false // Optional: skip cache
}
```

#### write

Atomic file write with automatic compression.

```json
{
  "path": "/path/to/file",
  "content": "file content"
}
```

#### batch_read

Concurrent reading of multiple files.

```json
{
  "paths": ["/path/to/file1", "/path/to/file2"]
}
```

#### batch_write

Parallel atomic writes for multiple files.

```json
{
  "files": [
    {
      "path": "/path/to/file1",
      "content": "content1"
    },
    {
      "path": "/path/to/file2",
      "content": "content2"
    }
  ]
}
```

### Directory Operations

#### ls

Lists directory contents.

```json
{
  "path": "/path/to/dir"
}
```

#### find

Recursive file search with pattern matching.

```json
{
  "path": "/search/start/path",
  "pattern": "search-term"
}
```

### System Operations

#### cache

Enable/disable the file caching system.

```json
{
  "enabled": true // or false to disable
}
```

#### info

Get file metadata.

```json
{
  "path": "/path/to/file"
}
// Returns: "{mode} {size} {modified-time}"
```

#### dirs

List allowed directories.

```json
{}
// Returns: One directory per line
```

## Performance Features

### Atomic Write Operations

- Uses temporary files for safe writing
- Ensures data integrity during crashes
- Proper fsync and permissions handling

### Caching System

- 5-minute TTL for cached files
- 50MB maximum cache size
- Automatic cache invalidation
- Per-request cache control
- Thread-safe operations

### Compression

- Automatic compression for files >1MB
- Transparent compression/decompression
- Only compresses if resulting size is smaller

### Concurrent Operations

- Parallel batch file operations
- Worker pool for file searches
- Thread-safe cache access
- Efficient resource utilization

## Security

- Strict path validation
- Symlink security checks
- Configurable allowed directories
- Parent directory verification
- Access control enforcement

## Error Handling

- Detailed error messages
- Automatic cleanup of temporary files
- Safe handling of partial operations
- Resource cleanup on failures

## Version History

### v0.4.0

- Added cache control system
- Implemented batch operations
- Added compression support
- Improved error handling

### v0.4.1

- Fixed working directory handling for relative paths
- Server now sets its working directory to first allowed directory
- Improved path validation for better file placement control
- Contributed by Martin Magala (martin@osl-ai.com)

### v0.3.0

- Added atomic write operations
- Implemented security checks
- Added basic file operations
