# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

htping is a CLI tool written in Go that performs HTTP/HTTPS pings to web endpoints and gathers various information about URLs. It's built using the Cobra CLI framework and provides networking utilities for web diagnostics.

## Architecture

- **Single-file architecture**: The entire application is contained in `main.go` (~700+ lines)
- **TUI-first design**: Uses Bubble Tea for beautiful terminal interfaces with fallback to simple mode
- **User-friendly onboarding**: Interactive welcome screen when no parameters provided
- **Command structure**: Uses Cobra CLI with ping as the default command:
  - `htping` - **Interactive welcome menu** with guided examples and tutorials
  - `htping <url>` - **Default ping command** with real-time TUI display showing live stats, emoji status indicators, and progress
  - `htping ping <url>` - Explicit ping command (same as default)
  - `htping info <url>` - Interactive TUI menu for information gathering with seamless navigation between ping and info modes
    - `htping info dns <url>` - DNS nameserver lookup
    - `htping info ip <url>` - IP address resolution
    - `htping info cert <url>` - TLS certificate details
    - `htping info whois <url>` - WHOIS information
- **Key dependencies**: cobra, bubbletea, lipgloss, whois, standard Go networking libraries

## Development Commands

### Build and Run
```bash
# Build the application
go build -o htping

# Launch interactive welcome screen
go run main.go

# Run with default ping behavior
go run main.go google.com
go run main.go google.com -c 5

# Run with explicit commands
go run main.go ping google.com
go run main.go info dns google.com
```

### Testing
```bash
# Run tests (if any exist)
go test ./...

# Build and test binary (default ping)
go build && ./htping google.com

# Test with count limit
go build && ./htping google.com -c 3

# Test info commands
go build && ./htping info dns google.com
```

### Module Management
```bash
# Download dependencies
go mod download

# Tidy dependencies
go mod tidy
```

## Key Implementation Details

- **TUI Models**: 
  - `WelcomeModel` - Interactive welcome screen with domain input, guided examples, and complete navigation
  - `HelpModel` - Comprehensive scrollable help screen with full documentation, controls guide, and examples
  - `PingModel` - Real-time ping display with live statistics, emoji status indicators, progress tracking, responsive sizing, and navigation to info/welcome
  - `InfoModel` - Interactive menu for selecting information type (DNS, IP, cert, WHOIS) with adaptive layout, back navigation, breadcrumbs, and welcome/ping mode switching
- **Terminal detection**: Automatically detects terminal availability and falls back to simple mode
- **Continuous pinging**: Uses count=0 for infinite pings with graceful Ctrl+C handling
- **Protocol detection**: Automatically prepends https:// or http:// based on --http flag
- **Styled output**: Uses Lipgloss for beautiful colors, borders, and formatting
- **Status indicators**: Emoji-based status indicators (✅ OK, 🔄 Redirect, 🚫 Client Error, 💥 Server Error)
- **HTML output**: Optional HTML content display/save with --html and --output flags
- **Domain parsing**: Helper functions `hasProtocol()`, `getRootDomain()`, and `extractHostFromURL()` for URL processing
- **Input handling**: Built-in text input using Bubbles textinput for domain entry with validation
- **State management**: Tracks navigation context (`fromWelcome` flag) for proper back navigation
- **Universal navigation**: Every screen provides clear path back to previous screen or welcome menu
- **Timeout handling**: 10-second HTTP client timeout for all requests

## Configuration

The application uses Go 1.24.4 and requires these external dependencies:
- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/lipgloss` - Terminal styling
- `github.com/likexian/whois` - WHOIS lookups
- `github.com/spf13/cobra` - CLI framework

## TUI Features

### Welcome Experience
- **Interactive welcome screen**: Launches when no parameters provided
- **Guided tutorial**: Shows usage examples and keyboard shortcuts
- **Quick start options**: Number keys (1-4) or navigation to launch demos
- **Built-in help system**: Interactive scrollable help screen with comprehensive documentation and controls guide
- **Graceful fallback**: Shows text-based help in non-interactive environments

### Core Features
- **Real-time ping display**: Live updating statistics with colorful progress indicators
- **Interactive info menu**: Navigate with arrow keys or j/k, select with Enter
- **Beautiful styling**: Rounded borders, color-coded status, emoji indicators
- **Fully responsive design**: 
  - Automatically detects and adapts to terminal window size
  - Handles window resizing in real-time without losing state
  - Adjusts content height based on available space (shows more/fewer ping results)
  - Truncates long content to fit terminal width
  - Scales box borders and padding dynamically
- **Smart content management**:
  - Shows recent ping results (limited by terminal height)
  - Truncates long error messages and URLs to fit width
  - Automatically wraps and limits info display results
- **Seamless navigation system**:
  - **From ping mode**: Press 'i' to switch to info menu, 'p' to pause/resume pinging
  - **In info menu**: Use arrow keys/j/k to navigate, Enter to select, Esc/b/backspace to go back
  - **Cross-mode transitions**: Switch between ping and info modes without losing context
  - **Breadcrumb navigation**: Shows current location (e.g., "Info Menu > DNS Servers")
  - **Smart menu options**: Info menu includes "Start HTTP Ping" option for easy mode switching
- **Enhanced controls**:
  - **Ping mode**: 'p' = pause/resume, 'i' = info menu, 'q' = quit
  - **Info mode**: ↑↓/j/k = navigate, Enter = select, Esc/b/backspace = back, 'q' = quit
- **Enhanced mouse support**: Enabled for better terminal interaction
- **Graceful fallback**: Works in non-interactive environments with simple text output