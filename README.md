# htping

[![Go](https://img.shields.io/badge/Go-1.26.6+-00ADD8?style=flat&logo=go&logoColor=white)](https://golang.org/)
[![Terminal](https://img.shields.io/badge/Terminal-TUI-brightgreen?style=flat&logo=gnometerminal&logoColor=white)](https://github.com/charmbracelet/bubbletea)
[![License](https://img.shields.io/badge/License-GPL%203.0-blue?style=flat&logo=gnu&logoColor=white)](LICENSE.md)

> A beautiful CLI tool for HTTP/HTTPS endpoint monitoring and web diagnostics with an interactive terminal interface.

## 🚀 Quick Start

```bash
# Interactive welcome screen with guided examples
htping

# Quick ping with real-time TUI
htping google.com

# Get comprehensive URL information
htping info github.com
```

## 📖 Overview

htping is a modern CLI utility that transforms web diagnostics with a stunning terminal interface. Built with Go and powered by Bubble Tea, it provides real-time HTTP monitoring, comprehensive web analysis, and an intuitive user experience that makes network debugging enjoyable.

**Key Highlights:**
- 🎨 **Beautiful TUI** - Responsive interface with live updates and emoji indicators
- ⚡ **Real-time Monitoring** - Live ping statistics with colorful progress tracking
- 🔍 **Deep Insights** - DNS, certificates, WHOIS, and IP information at your fingertips
- 🎯 **Smart Navigation** - Intuitive controls with seamless mode switching
- 🛡️ **Robust Design** - Graceful fallback for all environments

## ✨ Features

### 🎪 Interactive Experience
| Feature | Description |
|---------|-------------|
| **Welcome Screen** | Guided onboarding with interactive tutorials and examples |
| **Live Ping Display** | Real-time statistics with emoji status indicators (✅🔄🚫💥) |
| **Info Menu** | Navigate through DNS, IP, cert, and WHOIS data effortlessly |
| **Responsive Design** | Automatically adapts to terminal size with dynamic content |
| **Mouse Support** | Enhanced interaction with clickable elements |

### 🔧 Technical Capabilities
- ✅ **HTTP/HTTPS Monitoring** - Response time tracking with detailed statistics
- ✅ **DNS Analysis** - Authoritative nameserver lookups and resolution
- ✅ **IP Resolution** - Complete address mapping and network information
- ✅ **TLS Certificates** - Detailed certificate analysis and validation
- ✅ **WHOIS Lookup** - Domain registration and ownership details
- ✅ **Resource Analysis** - Page resource statistics (images, scripts, stylesheets, external hosts)
- ✅ **Performance Metrics** - Detailed timing breakdown (DNS, TCP, TLS, content transfer)
- ✅ **Geolocation** - Server location mapping with ISP and AS information
- ✅ **HTML Export** - Save and analyze page content
- ✅ **Protocol Detection** - Automatic HTTP/HTTPS handling
- ✅ **Timeout Management** - Configurable request timeouts
- ✅ **Authentication** - Basic and cookie authentication support
- ✅ **Response Caching** - Smart caching with configurable TTL (5 minutes)
- ✅ **Configurable Intervals** - Custom ping intervals in seconds
- ✅ **Comprehensive Reporting** - JSON and HTML exports with full ping and info data
- ✅ **Beautiful HTML Reports** - Professional reports with all diagnostic information

### 🚧 Roadmap
- 🔄 **Header Manipulation** - Custom header modification
- 🔄 **URL Crawling** - Regex-based site exploration
- 🔄 **CSV Export** - Additional export format support
- 🔄 **Multi-target Monitoring** - Parallel monitoring of multiple endpoints
- 🔄 **Advanced Auth** - OAuth and JWT token support

## 💻 Installation

### Option 1: Build from Source
```bash
git clone https://github.com/kubblai/htping.git
cd htping
go build -o htping
./htping
```

### Option 2: Development Mode
```bash
git clone https://github.com/kubblai/htping.git
cd htping
go run main.go google.com
```

## 🎮 Usage Guide

### Interactive Mode (Recommended)
```bash
htping                    # Launch welcome screen
htping example.com        # Quick ping with TUI
htping example.com -c 10  # Custom ping count
htping example.com -i 3   # Ping every 3 seconds
htping example.com --cache # Enable response caching
```

### Authentication Examples
```bash
# Basic authentication
htping example.com -u username -p password

# Cookie authentication
htping example.com --cookie "session=abc123; auth=xyz456"

# Combined with other options
htping example.com -u admin -p secret --cache -i 2 -c 10
```

### Direct Commands
```bash
# Ping operations
htping ping example.com                    # Default continuous pings
htping ping example.com -c 20              # Custom count
htping ping example.com --http             # Force HTTP
htping ping example.com --html -o page.html # Save HTML
htping ping example.com -i 5 --cache       # 5s intervals with caching

# Information gathering
htping info example.com        # Interactive menu
htping info dns example.com    # DNS servers
htping info ip example.com     # IP addresses  
htping info cert example.com   # TLS certificate
htping info whois example.com  # WHOIS data
htping info resources example.com  # Page resource statistics
htping info perf example.com   # Performance metrics
htping info geo example.com    # Geolocation information
```

### Export & Reporting Examples
```bash
# Export comprehensive ping data with all info
htping example.com -c 5 --export-json report.json
htping example.com -c 5 --export-html report.html

# Export with authentication and caching
htping secure-site.com -u user -p pass --cache --export-html secure-report.html

# Generate both JSON and HTML reports
htping api.example.com -c 10 -i 2 --export-json api-data.json --export-html api-report.html
```

## ⌨️ Navigation & Controls

Mouse tracking is disabled so you can drag to select text and use your terminal's normal copy shortcut while the TUI is running.

### 🏓 Ping Mode
| Key | Action |
|-----|--------|
| `p` | Pause/resume pinging |
| `i` | Switch to info menu |
| `q` | Quit application |
| `Ctrl+C` | Graceful exit |

### 📊 Info Mode  
| Key | Action |
|-----|--------|
| `↑↓` / `j k` | Navigate menu options |
| `Enter` | Select current option |
| `Esc` / `b` / `Backspace` | Return to previous screen |
| `q` | Quit application |

### 🏠 Welcome Screen
| Key | Action |
|-----|--------|
| `1-4` | Launch example demonstrations |
| `h` | Show comprehensive help |
| `↑↓` / `j k` | Navigate options |
| `Enter` | Execute selected action |

## 📋 Command Reference

### Global Flags
```bash
-h, --help              Show help information
-c, --count int         Number of requests (default: 0 = continuous)
-i, --interval int      Ping interval in seconds (default: 2)
    --http              Force HTTP instead of HTTPS  
    --html              Display HTML content after requests
-o, --output string     Save HTML content to file (requires --html)
-u, --username string   Basic authentication username
-p, --password string   Basic authentication password
    --cookie string     Cookie authentication string
    --cache             Enable response caching (5 minute TTL)
    --export-json string Export comprehensive report to JSON file
    --export-html string Export comprehensive report to HTML file
```

### Examples
```bash
# Continuous ping with custom interval
htping google.com -i 2

# Authenticated requests with caching
htping secure-site.com -u admin -p password --cache

# Cookie-based authentication
htping app.com --cookie "sessionid=abc123; csrftoken=xyz456"

# Combined authentication and performance analysis
htping api.example.com -u apikey -p secret -i 5 --cache

# HTTPS certificate analysis
htping info cert secure-site.com

# HTTP-only ping with HTML export
htping ping --http --html -o result.html http-site.com

# Quick DNS troubleshooting
htping info dns problematic-domain.com

# Website performance analysis with caching
htping info perf slow-site.com --cache

# Page resource breakdown
htping info resources complex-site.com

# Server location discovery
htping info geo international-site.com

# Comprehensive reporting
htping example.com -c 5 --export-json detailed-report.json
htping example.com -c 3 --export-html visual-report.html --cache

# Export with authentication
htping secure-api.com -u admin -p secret --export-html secure-analysis.html
```

## 🛠️ Development

### Prerequisites
- **Go 1.26.6+** - Latest Go installation
- **Color Terminal** - For optimal visual experience
- **Internet Connection** - Required for web requests

### Project Structure
```
htping/
├── main.go           # Single-file architecture (~700+ lines)
├── go.mod           # Go module dependencies  
├── go.sum           # Dependency checksums
├── CLAUDE.md        # Development guidelines
└── README.md        # This file
```

### Key Dependencies
| Package | Purpose |
|---------|---------|
| [`bubbletea`](https://github.com/charmbracelet/bubbletea) | TUI framework and event handling |
| [`lipgloss`](https://github.com/charmbracelet/lipgloss) | Terminal styling and layouts |
| [`cobra`](https://github.com/spf13/cobra) | CLI command structure |
| [`whois`](https://github.com/likexian/whois) | Domain information lookup |

### Build Commands
```bash
go mod download     # Install dependencies
go build           # Create binary
go test ./...      # Run tests (if present)
go mod tidy        # Clean dependencies
```

## 🤝 Contributing

We welcome contributions! Please feel free to:
- 🐛 Report bugs and issues
- 💡 Suggest new features  
- 🔧 Submit pull requests
- 📚 Improve documentation

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details.

---

<div align="center">
<b>Made with ❤️ and Go</b><br>
<i>Bringing beautiful diagnostics to your terminal</i>
</div>
