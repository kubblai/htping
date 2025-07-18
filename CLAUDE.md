# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

htping is a CLI tool written in Go that performs HTTP/HTTPS pings to web endpoints and gathers various information about URLs. It's built using the Cobra CLI framework and provides networking utilities for web diagnostics.

## Architecture

- **Single-file architecture**: The entire application is contained in `main.go` (280 lines)
- **Command structure**: Uses Cobra CLI with a root command and subcommands:
  - `htping ping <url>` - HTTP ping with response times and statistics
  - `htping info` - Parent command for information gathering
    - `htping info dns <url>` - DNS nameserver lookup
    - `htping info ip <url>` - IP address resolution
    - `htping info cert <url>` - TLS certificate details
    - `htping info whois <url>` - WHOIS information
- **Key dependencies**: cobra, color, whois, standard Go networking libraries

## Development Commands

### Build and Run
```bash
# Build the application
go build -o htping

# Run directly with Go
go run main.go ping <url>
go run main.go info dns <url>
```

### Testing
```bash
# Run tests (if any exist)
go test ./...

# Build and test binary
go build && ./htping ping google.com
```

### Module Management
```bash
# Download dependencies
go mod download

# Tidy dependencies
go mod tidy
```

## Key Implementation Details

- **Continuous pinging**: Uses count=0 for infinite pings with graceful Ctrl+C handling via signal channels
- **Protocol detection**: Automatically prepends https:// or http:// based on --http flag
- **Color-coded output**: Status codes are color-coded (green=2xx, yellow=3xx, red=4xx, blue=5xx)
- **HTML output**: Optional HTML content display/save with --html and --output flags
- **Domain parsing**: Helper functions `hasProtocol()` and `getRootDomain()` for URL processing
- **Timeout handling**: 10-second HTTP client timeout for all requests

## Configuration

The application uses Go 1.24.4 and requires these external dependencies:
- `github.com/fatih/color` - Terminal color output
- `github.com/likexian/whois` - WHOIS lookups
- `github.com/spf13/cobra` - CLI framework