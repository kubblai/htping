package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/likexian/whois"
	"github.com/spf13/cobra"
)

// Styles for TUI
var (
	headerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#04B575")).
		Bold(true).
		Padding(1, 2)

	successStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#04B575")).
		Bold(true)

	errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF6B6B")).
		Bold(true)

	warningStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFD93D")).
		Bold(true)

	infoStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6BCF7F"))

	statStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A78BFA")).
		Bold(true)

	boxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		BorderForeground(lipgloss.Color("#874BFD"))
)

// PingModel represents the state of the ping TUI
type PingModel struct {
	url           string
	responses     []PingResponse
	running       bool
	count         int
	current       int
	useHTTP       bool
	showHTML      bool
	outputFile    string
	client        *http.Client
	ip            string
	startTime     time.Time
	successCount  int
	totalDuration time.Duration
	width         int
	height        int
}

// PingResponse represents a single ping response
type PingResponse struct {
	StatusCode int
	Duration   time.Duration
	Error      error
	Timestamp  time.Time
}

// PingTickMsg represents a ping tick message
type PingTickMsg struct{}

// PingResultMsg represents a ping result message
type PingResultMsg struct {
	Response PingResponse
}

func (m *PingModel) Init() tea.Cmd {
	return tea.Batch(
		tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return PingTickMsg{}
		}),
		tea.WindowSize(),
	)
}

func (m *PingModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "i":
			// Switch to info menu
			infoModel := NewInfoModelWithSize(extractHostFromURL(m.url), m.width, m.height)
			return infoModel, nil
		case "w":
			// Go back to welcome menu
			welcomeModel := NewWelcomeModelWithSize(m.width, m.height)
			return welcomeModel, nil
		case "p", " ":
			// Pause/resume pinging
			m.running = !m.running
			if m.running {
				return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
					return PingTickMsg{}
				})
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Update box style with new dimensions
		boxStyle = boxStyle.Width(m.width - 4).Height(m.height - 4)
	case PingTickMsg:
		if m.running && (m.count <= 0 || m.current < m.count) {
			cmd := m.performPing()
			nextTick := tea.Tick(time.Second, func(t time.Time) tea.Msg {
				return PingTickMsg{}
			})
			return m, tea.Batch(cmd, nextTick)
		}
	case PingResultMsg:
		m.responses = append(m.responses, msg.Response)
		if msg.Response.Error == nil {
			m.successCount++
			m.totalDuration += msg.Response.Duration
		}
		m.current++
		if m.count > 0 && m.current >= m.count {
			m.running = false
		}
	}
	return m, nil
}

func (m *PingModel) View() string {
	if m.width == 0 || m.height == 0 {
		// Use default sizing if window size not set
		return m.renderContent(80, 24)
	}
	return m.renderContent(m.width, m.height)
}

func (m *PingModel) renderContent(width, height int) string {
	if len(m.responses) == 0 {
		content := headerStyle.Render(fmt.Sprintf("🌐 HTTP Pinging %s [%s]", m.url, m.ip)) + "\n\n" +
			infoStyle.Render("Starting ping...")
		return m.fitToTerminal(content, width, height)
	}

	// Header
	header := headerStyle.Render(fmt.Sprintf("🌐 HTTP Pinging %s [%s]", m.url, m.ip))

	// Calculate how many responses we can show based on terminal height
	availableHeight := height - 10 // Reserve space for header, stats, status, and padding
	if availableHeight < 3 {
		availableHeight = 3
	}

	// Recent responses (limited by available height)
	var recentResponses []string
	start := len(m.responses) - availableHeight
	if start < 0 {
		start = 0
	}

	for i := start; i < len(m.responses); i++ {
		resp := m.responses[i]
		var line string
		if resp.Error != nil {
			line = errorStyle.Render(fmt.Sprintf("❌ Error: %v", resp.Error))
		} else {
			var statusText string
			var style lipgloss.Style
			switch {
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				statusText = "✅ OK"
				style = successStyle
			case resp.StatusCode >= 300 && resp.StatusCode < 400:
				statusText = "🔄 Redirect"
				style = warningStyle
			case resp.StatusCode >= 400 && resp.StatusCode < 500:
				statusText = "🚫 Client Error"
				style = errorStyle
			case resp.StatusCode >= 500:
				statusText = "💥 Server Error"
				style = errorStyle
			default:
				statusText = "❓ Unknown"
				style = warningStyle
			}
			line = fmt.Sprintf("%s Status: %d, Time: %v",
				style.Render(statusText),
				resp.StatusCode,
				resp.Duration)
		}
		// Truncate long lines to fit terminal width
		if len(line) > width-6 {
			line = line[:width-9] + "..."
		}
		recentResponses = append(recentResponses, line)
	}

	// Statistics
	var stats string
	if m.successCount > 0 {
		avgDuration := m.totalDuration / time.Duration(m.successCount)
		stats = statStyle.Render(fmt.Sprintf("📊 Stats: %d/%d successful pings, Avg: %v",
			m.successCount, len(m.responses), avgDuration))
	} else {
		stats = statStyle.Render("📊 Stats: No successful pings yet")
	}

	// Status
	var status string
	if m.running {
		if m.count > 0 {
			status = infoStyle.Render(fmt.Sprintf("🔄 Running... (%d/%d)", m.current, m.count))
		} else {
			status = infoStyle.Render("🔄 Running... (continuous)")
		}
	} else {
		status = infoStyle.Render("✅ Completed")
	}

	// Controls help
	var controls string
	if m.running {
		controls = infoStyle.Render("Press 'p' to pause, 'i' for info menu, 'w' for welcome, 'q' to quit")
	} else if m.count > 0 && m.current >= m.count {
		controls = infoStyle.Render("Press 'i' for info menu, 'w' for welcome, 'q' to quit")
	} else {
		controls = infoStyle.Render("Press 'p' to resume, 'i' for info menu, 'w' for welcome, 'q' to quit")
	}

	content := header + "\n\n" +
		strings.Join(recentResponses, "\n") + "\n\n" +
		stats + "\n\n" +
		status + "\n\n" +
		controls

	return m.fitToTerminal(content, width, height)
}

func (m *PingModel) fitToTerminal(content string, width, height int) string {
	// Create a responsive box style
	responsiveBoxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		BorderForeground(lipgloss.Color("#874BFD")).
		Width(width - 4).
		Height(height - 4)

	return responsiveBoxStyle.Render(content)
}

func (m *PingModel) performPing() tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		resp, err := m.client.Get(m.url)
		duration := time.Since(start)

		if err != nil {
			return PingResultMsg{
				Response: PingResponse{
					Error:     err,
					Duration:  duration,
					Timestamp: time.Now(),
				},
			}
		}

		statusCode := resp.StatusCode
		resp.Body.Close()

		return PingResultMsg{
			Response: PingResponse{
				StatusCode: statusCode,
				Duration:   duration,
				Timestamp:  time.Now(),
			},
		}
	}
}

func main() {
	var pingCount int
	var useHTTP bool
	var showHTMLFlag bool
	var outputFilename string

	// Define ping function to be reused
	pingFunc := func(cmd *cobra.Command, args []string) {
		url := args[0]
		if !hasProtocol(url) {
			if useHTTP {
				url = "http://" + url
			} else {
				url = "https://" + url
			}
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
		}

		// Resolve IP address
		host := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
		ips, err := net.LookupIP(host)
		if err != nil {
			fmt.Printf("Error resolving IP: %v\n", err)
			return
		}
		ip := ips[0].String()

		// Create TUI model
		model := &PingModel{
			url:        url,
			running:    true,
			count:      pingCount,
			useHTTP:    useHTTP,
			showHTML:   showHTMLFlag,
			outputFile: outputFilename,
			client:     client,
			ip:        ip,
			startTime:  time.Now(),
		}

		// Start the TUI or fallback to simple mode
		if isTerminal() {
			p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
			if _, err := p.Run(); err != nil {
				fmt.Printf("Error running TUI: %v\n", err)
				return
			}
		} else {
			// Fallback to simple ping
			runSimplePing(url, ip, client, pingCount)
		}

		if showHTMLFlag {
			// Show HTML content
			showHTML(url, outputFilename)
		}
	}

	rootCmd := &cobra.Command{
		Use:   "htping [url]",
		Short: "HTTP ping tool with beautiful TUI interface",
		Long:  "htping is a CLI tool that performs HTTP/HTTPS pings to web endpoints and gathers various information about URLs.\n\nExamples:\n  htping google.com\n  htping google.com -c 5\n  htping info google.com",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// If no arguments, show interactive welcome menu
			if len(args) == 0 {
				if isTerminal() {
					welcomeModel := NewWelcomeModel()
					p := tea.NewProgram(welcomeModel, tea.WithAltScreen(), tea.WithMouseCellMotion())
					if _, err := p.Run(); err != nil {
						fmt.Printf("Error running welcome TUI: %v\n", err)
					}
				} else {
					showWelcomeText()
				}
				return
			}
			// Default behavior is ping
			pingFunc(cmd, args)
		},
	}

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Get information about a URL options are 'whois', 'dns', 'cert info'",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				fmt.Println("Please provide a URL")
				return
			}
			url := args[0]
			if isTerminal() {
				model := NewInfoModel(url)
				p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
				if _, err := p.Run(); err != nil {
					fmt.Printf("Error running TUI: %v\n", err)
				}
			} else {
				fmt.Printf("Please use specific subcommands: dns, ip, cert, whois\n")
			}
		},
	}

	dnsCmd := &cobra.Command{
		Use:   "dns <url>",
		Short: "Show authoritative nameservers for the URL",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ns, err := net.LookupNS(args[0])
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			for _, server := range ns {
				fmt.Println(server.Host)
			}
		},
	}

	ipCmd := &cobra.Command{
		Use:   "ip <url>",
		Short: "Show IP addresses for the URL",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ips, err := net.LookupIP(args[0])
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			for _, ip := range ips {
				fmt.Println(ip)
			}
		},
	}

	certCmd := &cobra.Command{
		Use:   "cert <url>",
		Short: "Show certificate details for HTTPS website",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			conn, err := tls.Dial("tcp", args[0]+":443", nil)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			defer conn.Close()
			cert := conn.ConnectionState().PeerCertificates[0]
			fmt.Printf("Subject: %s\n", cert.Subject)
			fmt.Printf("Issuer: %s\n", cert.Issuer)
			fmt.Printf("Valid from: %s\n", cert.NotBefore)
			fmt.Printf("Valid until: %s\n", cert.NotAfter)
		},
	}

	whoisCmd := &cobra.Command{
		Use:   "whois <url>",
		Short: "Show WHOIS information for the URL",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			domain := args[0]
			rootDomain := getRootDomain(domain)
			result, err := whois.Whois(rootDomain)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			fmt.Printf("WHOIS information for root domain: %s\n", rootDomain)
			fmt.Println(result)
		},
	}
	showHTMLCmd := &cobra.Command{
		Use:   "--html",
		Short: "Used with ping to show the HTML of the webpage",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			url := args[0]
			showHTML(url, outputFilename)
		},
	}

	pingCmd := &cobra.Command{
		Use:   "ping <url>",
		Short: "Perform HTTP(S) ping to the URL",
		Args:  cobra.ExactArgs(1),
		Run:   pingFunc,
	}

	// Initialize flags for both root and ping commands
	pingCmd.Flags().IntVarP(&pingCount, "count", "c", 0, "Number of pings to perform (0 for continuous)")
	pingCmd.Flags().BoolVar(&useHTTP, "http", false, "Use HTTP instead of HTTPS")
	pingCmd.Flags().BoolVar(&showHTMLFlag, "html", false, "Show HTML content after pings")
	pingCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Output filename for HTML content - use with --html")
	
	// Add the same flags to root command for default ping behavior
	rootCmd.Flags().IntVarP(&pingCount, "count", "c", 0, "Number of pings to perform (0 for continuous)")
	rootCmd.Flags().BoolVar(&useHTTP, "http", false, "Use HTTP instead of HTTPS")
	rootCmd.Flags().BoolVar(&showHTMLFlag, "html", false, "Show HTML content after pings")
	rootCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Output filename for HTML content - use with --html")

	// Add the output flag to showHTMLCmd as well
	showHTMLCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Output filename for HTML content - use with --html or htping html <url>")
	infoCmd.AddCommand(dnsCmd, ipCmd, certCmd, whoisCmd)
	rootCmd.AddCommand(infoCmd, pingCmd, showHTMLCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func hasProtocol(url string) bool {
	return len(url) > 7 && (url[:7] == "http://" || url[:8] == "https://")
}

func getRootDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// InfoModel represents the state of the info TUI
type InfoModel struct {
	url            string
	options        []string
	selected       int
	result         string
	loading        bool
	quit           bool
	width          int
	height         int
	showResult     bool // Track if we're showing result or menu
	lastAction     string // Track what info was last requested
	showPingOption bool // Show option to go to ping
	fromWelcome    bool // Track if we came from welcome screen
}

// NewInfoModel creates a new info model
func NewInfoModel(url string) *InfoModel {
	return &InfoModel{
		url:            url,
		options:        []string{"DNS Servers", "IP Addresses", "Certificate Info", "WHOIS Info", "---", "Start HTTP Ping"},
		selected:       0,
		showResult:     false,
		showPingOption: true,
		fromWelcome:    true,
	}
}

// NewInfoModelWithSize creates a new InfoModel with specified dimensions
func NewInfoModelWithSize(url string, width, height int) *InfoModel {
	m := NewInfoModel(url)
	m.width = width
	m.height = height
	m.fromWelcome = false
	return m
}

func (m *InfoModel) Init() tea.Cmd {
	return tea.WindowSize()
}

func (m *InfoModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "esc", "backspace", "b":
			// Go back to menu if showing result
			if m.showResult {
				m.showResult = false
				m.result = ""
				m.loading = false
			}
		case "w":
			// Go back to welcome menu if not showing result
			if !m.showResult && m.fromWelcome {
				welcomeModel := NewWelcomeModelWithSize(m.width, m.height)
				return welcomeModel, nil
			}
		case "up", "k":
			// Only allow navigation in menu mode
			if !m.showResult && m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			// Only allow navigation in menu mode
			if !m.showResult && m.selected < len(m.options)-1 {
				m.selected++
			}
		case "enter", " ":
			// Only allow selection in menu mode and when not loading
			if !m.showResult && !m.loading {
				// Check if "Start HTTP Ping" is selected
				if m.options[m.selected] == "Start HTTP Ping" {
					// Switch to ping mode
					pingModel := &PingModel{
						url:        "https://" + m.url,
						running:    true,
						count:      0, // Continuous
						client:     &http.Client{Timeout: 10 * time.Second},
						width:      m.width,
						height:     m.height,
						startTime:  time.Now(),
					}
					// Resolve IP for ping model
					ips, err := net.LookupIP(m.url)
					if err == nil && len(ips) > 0 {
						pingModel.ip = ips[0].String()
					} else {
						pingModel.ip = "unknown"
					}
					return pingModel, tea.Tick(time.Second, func(t time.Time) tea.Msg {
						return PingTickMsg{}
					})
				} else if m.options[m.selected] != "---" {
					// Regular info option
					m.loading = true
					m.lastAction = m.options[m.selected]
					return m, m.fetchInfo()
				}
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case InfoResultMsg:
		m.result = msg.Result
		m.loading = false
		m.showResult = true
	}
	return m, nil
}

func (m *InfoModel) View() string {
	if m.quit {
		return ""
	}

	width := m.width
	height := m.height
	if width == 0 || height == 0 {
		// Use default sizing if window size not set
		width = 80
		height = 24
	}

	header := headerStyle.Render(fmt.Sprintf("🔍 Info for %s", m.url))

	if m.loading {
		content := header + "\n\n" + 
			infoStyle.Render(fmt.Sprintf("🔄 Loading %s...", m.lastAction))
		return m.fitInfoToTerminal(content, width, height)
	}

	if m.showResult && m.result != "" {
		// Showing result view
		result := m.result
		lines := strings.Split(result, "\n")
		maxLines := height - 10 // Reserve space for header, breadcrumb, and footer
		if len(lines) > maxLines {
			lines = lines[:maxLines]
			lines = append(lines, "...")
			result = strings.Join(lines, "\n")
		}
		
		// Add breadcrumb
		breadcrumb := infoStyle.Render(fmt.Sprintf("🏠 Info Menu > %s", m.lastAction))
		
		var backInstructions string
		if m.fromWelcome {
			backInstructions = warningStyle.Render("← Press 'b'/'esc' to go back, 'w' for welcome") + "\n" +
				infoStyle.Render("Press 'q' to quit")
		} else {
			backInstructions = warningStyle.Render("← Press 'b', 'esc', or 'backspace' to go back") + "\n" +
				infoStyle.Render("Press 'q' to quit")
		}
		
		content := header + "\n\n" + 
			breadcrumb + "\n\n" +
			result + "\n\n" + 
			backInstructions
		return m.fitInfoToTerminal(content, width, height)
	}

	// Menu view
	var menu strings.Builder
	for i, option := range m.options {
		if option == "---" {
			// Separator
			menu.WriteString("\n")
			continue
		}
		if i == m.selected {
			if option == "Start HTTP Ping" {
				menu.WriteString(warningStyle.Render("> 🏃 " + option))
			} else {
				menu.WriteString(successStyle.Render("> " + option))
			}
		} else {
			if option == "Start HTTP Ping" {
				menu.WriteString("  🏃 " + option)
			} else {
				menu.WriteString("  " + option)
			}
		}
		menu.WriteString("\n")
	}

	var backOption string
	if m.fromWelcome {
		backOption = infoStyle.Render("Press 'w' for welcome menu, 'q' to quit")
	} else {
		backOption = infoStyle.Render("Press 'q' to quit")
	}

	content := header + "\n\n" +
		"Use ↑↓ or j/k to navigate, Enter to select:\n\n" +
		menu.String() + "\n" +
		backOption

	return m.fitInfoToTerminal(content, width, height)
}

func (m *InfoModel) fitInfoToTerminal(content string, width, height int) string {
	// Create a responsive box style
	responsiveBoxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		BorderForeground(lipgloss.Color("#874BFD")).
		Width(width - 4).
		Height(height - 4)

	return responsiveBoxStyle.Render(content)
}

// InfoResultMsg represents the result of an info operation
type InfoResultMsg struct {
	Result string
}

func (m *InfoModel) fetchInfo() tea.Cmd {
	return func() tea.Msg {
		var result string
		switch m.selected {
		case 0: // DNS
			ns, err := net.LookupNS(m.url)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error: %v", err))
			} else {
				result = successStyle.Render("🌐 DNS Servers:") + "\n\n"
				for _, server := range ns {
					result += fmt.Sprintf("  • %s\n", server.Host)
				}
			}
		case 1: // IP
			ips, err := net.LookupIP(m.url)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error: %v", err))
			} else {
				result = successStyle.Render("🌐 IP Addresses:") + "\n\n"
				for _, ip := range ips {
					result += fmt.Sprintf("  • %s\n", ip.String())
				}
			}
		case 2: // Certificate
			conn, err := tls.Dial("tcp", m.url+":443", nil)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error: %v", err))
			} else {
				defer conn.Close()
				cert := conn.ConnectionState().PeerCertificates[0]
				result = successStyle.Render("🔒 Certificate Info:") + "\n\n" +
					fmt.Sprintf("  • Subject: %s\n", cert.Subject) +
					fmt.Sprintf("  • Issuer: %s\n", cert.Issuer) +
					fmt.Sprintf("  • Valid from: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05")) +
					fmt.Sprintf("  • Valid until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
			}
		case 3: // WHOIS
			domain := getRootDomain(m.url)
			whoisResult, err := whois.Whois(domain)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error: %v", err))
			} else {
				result = successStyle.Render(fmt.Sprintf("📜 WHOIS Info for %s:", domain)) + "\n\n" +
					whoisResult
			}
		}
		return InfoResultMsg{Result: result}
	}
}

// isTerminal checks if we're running in a terminal
func isTerminal() bool {
	// Check if stdout is a terminal
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// runSimplePing runs ping in simple mode without TUI
func runSimplePing(url, ip string, client *http.Client, count int) {
	fmt.Printf("Http pinging %s [%s]\n\n", url, ip)

	var totalDuration time.Duration
	var successfulPings int

	for i := 0; i < count || count <= 0; i++ {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		duration := time.Since(start)
		totalDuration += duration
		successfulPings++

		statusCode := resp.StatusCode
		var statusText string
		switch {
		case statusCode >= 200 && statusCode < 300:
			statusText = "✅ OK"
		case statusCode >= 300 && statusCode < 400:
			statusText = "🔄 Redirect"
		case statusCode >= 400 && statusCode < 500:
			statusText = "🚫 Client Error"
		case statusCode >= 500:
			statusText = "💥 Server Error"
		default:
			statusText = "❓ Unknown"
		}

		fmt.Printf("Status: %d %s, Time: %v\n", statusCode, statusText, duration)
		resp.Body.Close()

		if count > 0 && i >= count-1 {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if successfulPings > 0 {
		avgDuration := totalDuration / time.Duration(successfulPings)
		fmt.Printf("\nAverage response time: %v\n", avgDuration)
		fmt.Printf("Total successful pings: %d\n", successfulPings)
	} else {
		fmt.Println("\nNo successful pings")
	}
}

// showHTML fetches and displays HTML content
func showHTML(url, outputFilename string) {
	if !hasProtocol(url) {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error fetching HTML: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading HTML: %v\n", err)
		return
	}

	if outputFilename != "" {
		err := os.WriteFile(outputFilename, body, 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}
		fmt.Printf("HTML content saved to %s\n", outputFilename)
	} else {
		fmt.Printf("\nHTML Content:\n%s\n", string(body))
	}
}

// extractHostFromURL extracts the hostname from a URL
func extractHostFromURL(url string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
	// Remove path if present
	if slashIndex := strings.Index(host, "/"); slashIndex != -1 {
		host = host[:slashIndex]
	}
	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	return host
}

// WelcomeModel represents the welcome screen TUI
type WelcomeModel struct {
	selected      int
	options       []WelcomeOption
	width         int
	height        int
	quit          bool
	showingInput  bool
	inputMode     string // "ping" or "info"
	textInput     textinput.Model
}

// WelcomeOption represents a menu option
type WelcomeOption struct {
	Title       string
	Description string
	Example     string
	Action      string
}

// NewWelcomeModel creates a new welcome model
func NewWelcomeModel() *WelcomeModel {
	ti := textinput.New()
	ti.Placeholder = "Enter domain (e.g., google.com, github.com)"
	ti.Focus()
	ti.CharLimit = 100
	ti.Width = 50

	return &WelcomeModel{
		selected: 0,
		textInput: ti,
		options: []WelcomeOption{
			{
				Title:       "🌐 HTTP Ping",
				Description: "Ping a website and see response times",
				Example:     "htping google.com",
				Action:      "ping",
			},
			{
				Title:       "🔍 Domain Info",
				Description: "Get DNS, IP, certificate, and WHOIS information",
				Example:     "htping info google.com",
				Action:      "info",
			},
			{
				Title:       "🏃 Quick Demo",
				Description: "Try ping and info with google.com",
				Example:     "Interactive demo",
				Action:      "demo",
			},
			{
				Title:       "📖 View Help",
				Description: "Show detailed help and all available commands",
				Example:     "htping --help",
				Action:      "help",
			},
			{
				Title:       "🚪 Exit",
				Description: "Exit the application",
				Example:     "",
				Action:      "quit",
			},
		},
	}
}

// NewWelcomeModelWithSize creates a new WelcomeModel with specified dimensions
func NewWelcomeModelWithSize(width, height int) *WelcomeModel {
	m := NewWelcomeModel()
	m.width = width
	m.height = height
	return m
}

func (m *WelcomeModel) Init() tea.Cmd {
	return tea.WindowSize()
}

func (m *WelcomeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showingInput {
			switch msg.String() {
			case "enter":
				// Submit input
				domain := strings.TrimSpace(m.textInput.Value())
				if domain != "" {
					return m.launchWithDomain(domain)
				}
			case "esc":
				// Go back to menu
				m.showingInput = false
				m.textInput.SetValue("")
				m.textInput.Blur()
			default:
				// Handle text input
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
		} else {
			switch msg.String() {
			case "q", "ctrl+c":
				m.quit = true
				return m, tea.Quit
			case "up", "k":
				if m.selected > 0 {
					m.selected--
				}
			case "down", "j":
				if m.selected < len(m.options)-1 {
					m.selected++
				}
			case "enter", " ":
				return m.handleSelection()
			case "1":
				m.selected = 0
				return m.handleSelection()
			case "2":
				m.selected = 1
				return m.handleSelection()
			case "3":
				m.selected = 2
				return m.handleSelection()
			case "4":
				m.selected = 3
				return m.handleSelection()
			case "5":
				m.selected = 4
				return m.handleSelection()
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}
	return m, nil
}

func (m *WelcomeModel) handleSelection() (tea.Model, tea.Cmd) {
	selectedOption := m.options[m.selected]
	
	switch selectedOption.Action {
	case "ping":
		// Show input for domain
		m.showingInput = true
		m.inputMode = "ping"
		m.textInput.Focus()
		m.textInput.SetValue("")
	case "info":
		// Show input for domain
		m.showingInput = true
		m.inputMode = "info"
		m.textInput.Focus()
		m.textInput.SetValue("")
	case "demo":
		// Launch demo with google.com
		return m.launchWithDomain("google.com")
	case "help":
		// Show help screen
		helpModel := NewHelpModel()
		helpModel.width = m.width
		helpModel.height = m.height
		return helpModel, nil
	case "quit":
		m.quit = true
		return m, tea.Quit
	}
	return m, nil
}

func (m *WelcomeModel) launchWithDomain(domain string) (tea.Model, tea.Cmd) {
	// Clean up domain input
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")
	
	if m.inputMode == "ping" || m.inputMode == "" {
		// Launch ping
		pingModel := &PingModel{
			url:       "https://" + domain,
			running:   true,
			count:     0, // Continuous
			client:    &http.Client{Timeout: 10 * time.Second},
			width:     m.width,
			height:    m.height,
			startTime: time.Now(),
		}
		// Resolve IP
		ips, err := net.LookupIP(domain)
		if err == nil && len(ips) > 0 {
			pingModel.ip = ips[0].String()
		} else {
			pingModel.ip = "unknown"
		}
		return pingModel, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return PingTickMsg{}
		})
	} else {
		// Launch info menu
		infoModel := NewInfoModelWithSize(domain, m.width, m.height)
		infoModel.fromWelcome = true
		return infoModel, nil
	}
}

func (m *WelcomeModel) View() string {
	if m.quit {
		return ""
	}

	width := m.width
	height := m.height
	if width == 0 || height == 0 {
		width = 80
		height = 24
	}

	// Title
	title := headerStyle.Render("🚀 Welcome to htping!")
	description := infoStyle.Render("A beautiful HTTP ping tool with TUI interface")

	if m.showingInput {
		// Show input screen
		var actionTitle string
		if m.inputMode == "ping" {
			actionTitle = "🌐 HTTP Ping"
		} else {
			actionTitle = "🔍 Domain Info"
		}
		
		inputTitle := successStyle.Render(actionTitle)
		inputPrompt := infoStyle.Render("Enter the domain you want to " + strings.ToLower(strings.TrimPrefix(actionTitle, "🌐 ")) + ":")
		
		content := title + "\n" + description + "\n\n" +
			inputTitle + "\n\n" +
			inputPrompt + "\n\n" +
			m.textInput.View() + "\n\n" +
			warningStyle.Render("Press Enter to continue, Esc to go back")
		
		// Create responsive box
		responsiveBoxStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2).
			BorderForeground(lipgloss.Color("#874BFD")).
			Width(width - 4).
			Height(height - 4)
		
		return responsiveBoxStyle.Render(content)
	}

	// Menu options
	var menu strings.Builder
	for i, option := range m.options {
		prefix := fmt.Sprintf("[%d] ", i+1)
		if i == m.selected {
			menu.WriteString(successStyle.Render("> " + prefix + option.Title))
			menu.WriteString("\n    " + infoStyle.Render(option.Description))
			if option.Example != "" {
				menu.WriteString("\n    " + statStyle.Render("Example: "+option.Example))
			}
		} else {
			menu.WriteString("  " + prefix + option.Title)
			menu.WriteString("\n    " + option.Description)
			if option.Example != "" {
				menu.WriteString("\n    " + "Example: " + option.Example)
			}
		}
		menu.WriteString("\n\n")
	}

	// Instructions
	instructions := infoStyle.Render(
		"Navigation: ↑↓ or j/k to navigate, Enter or number keys to select, q to quit")

	// Quick start examples
	examples := warningStyle.Render("Quick Start Examples:") + "\n" +
		"  htping google.com                    # Ping a website\n" +
		"  htping google.com -c 5               # Ping 5 times\n" +
		"  htping info github.com               # Get domain info\n" +
		"  htping info dns stackoverflow.com    # Get DNS info\n"

	content := title + "\n" + description + "\n\n" +
		menu.String() +
		examples + "\n\n" +
		instructions

	// Create responsive box
	responsiveBoxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		BorderForeground(lipgloss.Color("#874BFD")).
		Width(width - 4).
		Height(height - 4)

	return responsiveBoxStyle.Render(content)
}

// showWelcomeText shows welcome text for non-interactive environments
func showWelcomeText() {
	fmt.Println("🚀 Welcome to htping!")
	fmt.Println("A beautiful HTTP ping tool with TUI interface")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  htping <url>                    # HTTP ping (default)")
	fmt.Println("  htping ping <url>               # Explicit ping command")
	fmt.Println("  htping info <url>               # Domain information menu")
	fmt.Println("  htping info dns <url>           # DNS nameservers")
	fmt.Println("  htping info ip <url>            # IP addresses")
	fmt.Println("  htping info cert <url>          # TLS certificate info")
	fmt.Println("  htping info whois <url>         # WHOIS information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  htping google.com")
	fmt.Println("  htping google.com -c 5")
	fmt.Println("  htping info github.com")
	fmt.Println("  htping info dns stackoverflow.com")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c, --count int       Number of pings (0 for continuous)")
	fmt.Println("      --http            Use HTTP instead of HTTPS")
	fmt.Println("      --html            Show HTML content after pings")
	fmt.Println("  -o, --output string   Output filename for HTML content")
	fmt.Println()
	fmt.Println("TUI Controls:")
	fmt.Println("  Ping mode: 'p' = pause/resume, 'i' = info menu, 'q' = quit")
	fmt.Println("  Info mode: ↑↓/j/k = navigate, Enter = select, Esc/b = back, 'q' = quit")
	fmt.Println()
	fmt.Println("For more help: htping --help")
}

// HelpModel represents the help screen TUI
type HelpModel struct {
	width    int
	height   int
	quit     bool
	scroll   int
	content  []string
}

// NewHelpModel creates a new help model
func NewHelpModel() *HelpModel {
	content := []string{
		"🚀 htping - HTTP Ping Tool with Beautiful TUI",
		"",
		"DESCRIPTION:",
		"  htping is a CLI tool that performs HTTP/HTTPS pings to web endpoints",
		"  and gathers various information about URLs with a beautiful TUI interface.",
		"",
		"USAGE:",
		"  htping                          # Interactive welcome menu",
		"  htping <url>                    # HTTP ping (default)",
		"  htping ping <url>               # Explicit ping command",
		"  htping info <url>               # Domain information menu",
		"  htping info dns <url>           # DNS nameservers",
		"  htping info ip <url>            # IP addresses",
		"  htping info cert <url>          # TLS certificate info",
		"  htping info whois <url>         # WHOIS information",
		"",
		"EXAMPLES:",
		"  htping google.com               # Continuous ping",
		"  htping google.com -c 5          # Ping 5 times",
		"  htping google.com --http        # Use HTTP instead of HTTPS",
		"  htping info github.com          # Interactive info menu",
		"  htping info dns stackoverflow.com # DNS lookup",
		"  htping google.com --html -o page.html # Save HTML content",
		"",
		"OPTIONS:",
		"  -c, --count int       Number of pings (0 for continuous)",
		"      --http            Use HTTP instead of HTTPS",
		"      --html            Show HTML content after pings",
		"  -o, --output string   Output filename for HTML content",
		"  -h, --help            Show this help message",
		"",
		"TUI CONTROLS:",
		"",
		"Welcome Menu:",
		"  ↑↓ or j/k         Navigate options",
		"  Enter               Select option",
		"  1-5                 Quick select by number",
		"  q                   Quit application",
		"",
		"Domain Input:",
		"  Type domain name    Enter any domain (e.g., google.com)",
		"  Enter               Submit and launch",
		"  Esc                 Back to welcome menu",
		"",
		"Ping Mode:",
		"  p or Space          Pause/resume pinging",
		"  i                   Switch to info menu",
		"  w                   Return to welcome menu",
		"  q or Ctrl+C         Quit application",
		"",
		"Info Menu:",
		"  ↑↓ or j/k         Navigate options",
		"  Enter               Select info type",
		"  b, Esc, Backspace   Go back (context-sensitive)",
		"  w                   Return to welcome menu",
		"  q                   Quit application",
		"",
		"Info Results:",
		"  b, Esc, Backspace   Back to info menu",
		"  w                   Return to welcome menu",
		"  q                   Quit application",
		"",
		"FEATURES:",
		"  • Real-time ping display with live statistics",
		"  • Beautiful TUI with emoji status indicators",
		"  • Responsive design that adapts to terminal size",
		"  • Interactive navigation between all modes",
		"  • Domain information gathering (DNS, IP, cert, WHOIS)",
		"  • HTML content display and saving",
		"  • Graceful fallback for non-interactive environments",
		"  • Universal back navigation",
		"",
		"STATUS INDICATORS:",
		"  ✅ 200-299          Success (OK)",
		"  🔄 300-399          Redirection",
		"  🚫 400-499          Client Error",
		"  💥 500-599          Server Error",
		"  ❓ Other            Unknown status",
		"",
		"NAVIGATION FLOW:",
		"  htping (no args) → Welcome Menu → Domain Input → Ping/Info Mode",
		"  Any mode → 'w' key → Welcome Menu",
		"  Info Results → 'b'/Esc → Info Menu → 'w' → Welcome",
		"",
		"For more information, visit: https://github.com/kubblai/htping",
	}

	return &HelpModel{
		content: content,
		scroll:  0,
	}
}

func (m *HelpModel) Init() tea.Cmd {
	return tea.WindowSize()
}

func (m *HelpModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "esc", "b", "w":
			// Go back to welcome
			welcomeModel := NewWelcomeModelWithSize(m.width, m.height)
			return welcomeModel, nil
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "down", "j":
			maxScroll := len(m.content) - (m.height - 8) // Reserve space for borders and instructions
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.scroll < maxScroll {
				m.scroll++
			}
		case "home":
			m.scroll = 0
		case "end":
			maxScroll := len(m.content) - (m.height - 8)
			if maxScroll < 0 {
				maxScroll = 0
			}
			m.scroll = maxScroll
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}
	return m, nil
}

func (m *HelpModel) View() string {
	if m.quit {
		return ""
	}

	width := m.width
	height := m.height
	if width == 0 || height == 0 {
		width = 80
		height = 24
	}

	// Header
	header := headerStyle.Render("📖 htping Help")

	// Calculate visible content
	visibleHeight := height - 8 // Reserve space for header, footer, borders
	if visibleHeight < 3 {
		visibleHeight = 3
	}

	startLine := m.scroll
	endLine := startLine + visibleHeight
	if endLine > len(m.content) {
		endLine = len(m.content)
	}

	// Build visible content
	var contentLines []string
	for i := startLine; i < endLine; i++ {
		line := m.content[i]
		// Truncate long lines to fit width
		if len(line) > width-8 {
			line = line[:width-11] + "..."
		}
		contentLines = append(contentLines, line)
	}

	// Scroll indicators
	var scrollInfo string
	if len(m.content) > visibleHeight {
		scrollInfo = statStyle.Render(fmt.Sprintf("Line %d-%d of %d", startLine+1, endLine, len(m.content)))
	}

	// Instructions
	instructions := infoStyle.Render("↑↓/j/k to scroll, Home/End for top/bottom, w/b/Esc to go back, q to quit")

	content := header + "\n\n" +
		strings.Join(contentLines, "\n") + "\n\n"

	if scrollInfo != "" {
		content += scrollInfo + "\n"
	}
	content += instructions

	// Create responsive box
	responsiveBoxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		BorderForeground(lipgloss.Color("#874BFD")).
		Width(width - 4).
		Height(height - 4)

	return responsiveBoxStyle.Render(content)
}
