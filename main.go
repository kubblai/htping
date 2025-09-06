package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
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

// CacheEntry represents a cached HTTP response
type CacheEntry struct {
	Response   *http.Response
	Body       []byte
	Timestamp  time.Time
	StatusCode int
	Headers    http.Header
}

// ResponseCache provides thread-safe caching for HTTP responses
type ResponseCache struct {
	cache    map[string]*CacheEntry
	mutex    sync.RWMutex
	ttl      time.Duration
}

// NewResponseCache creates a new response cache with specified TTL
func NewResponseCache(ttl time.Duration) *ResponseCache {
	return &ResponseCache{
		cache: make(map[string]*CacheEntry),
		ttl:   ttl,
	}
}

// Get retrieves a cached response if available and not expired
func (c *ResponseCache) Get(key string) (*CacheEntry, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}
	
	// Check if entry is expired
	if time.Since(entry.Timestamp) > c.ttl {
		delete(c.cache, key)
		return nil, false
	}
	
	return entry, true
}

// Set stores a response in the cache
func (c *ResponseCache) Set(key string, entry *CacheEntry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.cache[key] = entry
}

// Clear removes all entries from cache
func (c *ResponseCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.cache = make(map[string]*CacheEntry)
}

// generateCacheKey creates a unique key for caching based on URL and auth
func generateCacheKey(url, auth string) string {
	data := url + ":" + auth
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// Global cache instance
var globalCache = NewResponseCache(5 * time.Minute)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	BasicAuth   BasicAuthConfig
	CookieAuth  string
	UseBasic    bool
	UseCookie   bool
}

// BasicAuthConfig holds basic authentication credentials
type BasicAuthConfig struct {
	Username string
	Password string
}

// configureAuthentication sets up authentication headers for HTTP client
func configureAuthentication(req *http.Request, authConfig AuthConfig) {
	if authConfig.UseBasic && authConfig.BasicAuth.Username != "" {
		auth := authConfig.BasicAuth.Username + ":" + authConfig.BasicAuth.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Authorization", "Basic "+encoded)
	}
	
	if authConfig.UseCookie && authConfig.CookieAuth != "" {
		req.Header.Set("Cookie", authConfig.CookieAuth)
	}
}

// ReportData contains all data for comprehensive reporting
type ReportData struct {
	Metadata    ReportMetadata    `json:"metadata"`
	Target      TargetInfo       `json:"target"`
	PingResults PingResults      `json:"ping_results"`
	InfoData    InfoData         `json:"info_data"`
	Statistics  Statistics       `json:"statistics"`
	Generated   time.Time        `json:"generated"`
}

// ReportMetadata contains information about the report
type ReportMetadata struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Command     string    `json:"command"`
	Duration    string    `json:"duration"`
	ReportType  string    `json:"report_type"`
}

// TargetInfo contains information about the target URL
type TargetInfo struct {
	URL          string            `json:"url"`
	Host         string            `json:"host"`
	Protocol     string            `json:"protocol"`
	Port         string            `json:"port,omitempty"`
	Authentication AuthInfo        `json:"authentication,omitempty"`
	Options      TargetOptions    `json:"options"`
}

// AuthInfo contains authentication details (sanitized)
type AuthInfo struct {
	Type        string `json:"type"`
	Username    string `json:"username,omitempty"`
	HasPassword bool   `json:"has_password,omitempty"`
	HasCookie   bool   `json:"has_cookie,omitempty"`
}

// TargetOptions contains request options
type TargetOptions struct {
	Interval   string `json:"interval"`
	Count      int    `json:"count"`
	UseCache   bool   `json:"use_cache"`
	Timeout    string `json:"timeout"`
}

// PingResults contains all ping response data
type PingResults struct {
	Responses []DetailedPingResponse `json:"responses"`
	Summary   PingSummary           `json:"summary"`
}

// DetailedPingResponse extends PingResponse with additional data
type DetailedPingResponse struct {
	PingResponse
	Index       int           `json:"index"`
	FromCache   bool          `json:"from_cache"`
	Headers     http.Header   `json:"headers,omitempty"`
	ContentType string        `json:"content_type,omitempty"`
	ContentSize int64         `json:"content_size,omitempty"`
}

// PingSummary contains aggregated ping statistics
type PingSummary struct {
	TotalPings    int           `json:"total_pings"`
	Successful    int           `json:"successful"`
	Failed        int           `json:"failed"`
	CachedHits    int           `json:"cached_hits"`
	AvgDuration   time.Duration `json:"avg_duration"`
	MinDuration   time.Duration `json:"min_duration"`
	MaxDuration   time.Duration `json:"max_duration"`
	SuccessRate   float64       `json:"success_rate"`
}

// InfoData contains all information gathering results
type InfoData struct {
	DNS         DNSInfo         `json:"dns,omitempty"`
	IP          IPInfo          `json:"ip,omitempty"`
	Certificate CertificateInfo `json:"certificate,omitempty"`
	WHOIS       WHOISInfo       `json:"whois,omitempty"`
	Resources   *ResourceStats  `json:"resources,omitempty"`
	Performance *PerformanceMetrics `json:"performance,omitempty"`
	Geolocation *GeoLocation    `json:"geolocation,omitempty"`
}

// DNSInfo contains DNS lookup results
type DNSInfo struct {
	Nameservers []string  `json:"nameservers"`
	LookupTime  time.Duration `json:"lookup_time"`
	Error       string    `json:"error,omitempty"`
}

// IPInfo contains IP resolution results
type IPInfo struct {
	Addresses   []string      `json:"addresses"`
	IPv4        []string      `json:"ipv4"`
	IPv6        []string      `json:"ipv6"`
	LookupTime  time.Duration `json:"lookup_time"`
	Error       string        `json:"error,omitempty"`
}

// CertificateInfo contains TLS certificate details
type CertificateInfo struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	IsValid        bool      `json:"is_valid"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	SignatureAlg   string    `json:"signature_algorithm"`
	Error          string    `json:"error,omitempty"`
}

// WHOISInfo contains WHOIS lookup results
type WHOISInfo struct {
	Domain      string        `json:"domain"`
	RawData     string        `json:"raw_data"`
	LookupTime  time.Duration `json:"lookup_time"`
	Error       string        `json:"error,omitempty"`
}

// Statistics contains overall statistics
type Statistics struct {
	TotalDuration    time.Duration `json:"total_duration"`
	AverageInterval  time.Duration `json:"average_interval"`
	DataTransferred  int64         `json:"data_transferred"`
	RequestsPerSecond float64      `json:"requests_per_second"`
}

// PingModel represents the state of the ping TUI
type PingModel struct {
	url              string
	responses        []PingResponse
	detailedResponses []DetailedPingResponse
	running          bool
	count            int
	current          int
	useHTTP          bool
	showHTML         bool
	outputFile       string
	client           *http.Client
	ip               string
	startTime        time.Time
	successCount     int
	totalDuration    time.Duration
	width            int
	height           int
	authConfig       AuthConfig
	useCache         bool
	interval         time.Duration
	reportData       *ReportData
	exportJSON       string
	exportHTML       string
	exportStatus     string
}

// PingResponse represents a single ping response
type PingResponse struct {
	StatusCode int
	Duration   time.Duration
	Error      error
	Timestamp  time.Time
	Resources  *ResourceStats     `json:"resources,omitempty"`
	Performance *PerformanceMetrics `json:"performance,omitempty"`
}

// ResourceStats contains page resource statistics
type ResourceStats struct {
	TotalResources int              `json:"total_resources"`
	Images         int              `json:"images"`
	Scripts        int              `json:"scripts"`
	Stylesheets    int              `json:"stylesheets"`
	Links          int              `json:"links"`
	ContentLength  int64            `json:"content_length"`
	ResourceTypes  map[string]int   `json:"resource_types"`
	ExternalHosts  map[string]int   `json:"external_hosts"`
	TotalSize      int64            `json:"total_size"`
}

// PerformanceMetrics contains detailed performance data
type PerformanceMetrics struct {
	DNSLookup     time.Duration `json:"dns_lookup"`
	TCPConnect    time.Duration `json:"tcp_connect"`
	TLSHandshake  time.Duration `json:"tls_handshake"`
	ServerProcess time.Duration `json:"server_process"`
	ContentTransfer time.Duration `json:"content_transfer"`
	FirstByteTime time.Duration `json:"first_byte_time"`
	ResponseSize  int64         `json:"response_size"`
	Redirects     int           `json:"redirects"`
	Protocol      string        `json:"protocol"`
}

// GeoLocation contains geographical information
type GeoLocation struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	ASName      string  `json:"asname"`
	Success     bool    `json:"success"`
	Message     string  `json:"message,omitempty"`
}

// PingTickMsg represents a ping tick message
type PingTickMsg struct{}

// PingResultMsg represents a ping result message
type PingResultMsg struct {
	Response         PingResponse
	DetailedResponse *DetailedPingResponse
}

// ReportGeneratedMsg signals that reports have been generated
type ReportGeneratedMsg struct{}

func (m *PingModel) Init() tea.Cmd {
	return tea.Batch(
		tea.Tick(m.interval, func(t time.Time) tea.Msg {
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
				return m, tea.Tick(m.interval, func(t time.Time) tea.Msg {
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
			nextTick := tea.Tick(m.interval, func(t time.Time) tea.Msg {
				return PingTickMsg{}
			})
			return m, tea.Batch(cmd, nextTick)
		}
	case PingResultMsg:
		m.responses = append(m.responses, msg.Response)
		if msg.DetailedResponse != nil {
			m.detailedResponses = append(m.detailedResponses, *msg.DetailedResponse)
		}
		if msg.Response.Error == nil {
			m.successCount++
			m.totalDuration += msg.Response.Duration
		}
		m.current++
		if m.count > 0 && m.current >= m.count {
			m.running = false
			// Generate report if export options are specified
			if m.exportJSON != "" || m.exportHTML != "" {
				return m, func() tea.Msg {
					m.generateReport()
					return ReportGeneratedMsg{}
				}
			}
		}
	case ReportGeneratedMsg:
		// Report generation is complete, just refresh the UI
		return m, nil
	}
	return m, nil
}

// generateReport creates and exports the comprehensive report
func (m *PingModel) generateReport() {
	if m.reportData == nil {
		m.reportData = &ReportData{}
	}

	// Fill in report metadata
	m.reportData.Metadata = ReportMetadata{
		Tool:       "htping",
		Version:    "1.0.0",
		Command:    fmt.Sprintf("htping %s", m.url),
		Duration:   time.Since(m.startTime).String(),
		ReportType: "ping-report",
	}

	// Fill in target information
	parsedURL, _ := url.Parse(m.url)
	authInfo := AuthInfo{}
	if m.authConfig.UseBasic {
		authInfo.Type = "basic"
		authInfo.Username = m.authConfig.BasicAuth.Username
		authInfo.HasPassword = m.authConfig.BasicAuth.Password != ""
	}
	if m.authConfig.UseCookie {
		if authInfo.Type != "" {
			authInfo.Type += "+cookie"
		} else {
			authInfo.Type = "cookie"
		}
		authInfo.HasCookie = true
	}

	m.reportData.Target = TargetInfo{
		URL:      m.url,
		Host:     parsedURL.Host,
		Protocol: parsedURL.Scheme,
		Port:     parsedURL.Port(),
		Authentication: authInfo,
		Options: TargetOptions{
			Interval: m.interval.String(),
			Count:    m.count,
			UseCache: m.useCache,
			Timeout:  "10s",
		},
	}

	// Calculate ping statistics
	var minDuration, maxDuration time.Duration
	var totalDuration time.Duration
	successCount := 0
	cachedCount := 0
	
	if len(m.detailedResponses) > 0 {
		minDuration = time.Duration(1<<63 - 1) // Max duration
		for _, resp := range m.detailedResponses {
			if resp.Error == nil {
				successCount++
				totalDuration += resp.Duration
				if resp.Duration < minDuration {
					minDuration = resp.Duration
				}
				if resp.Duration > maxDuration {
					maxDuration = resp.Duration
				}
				if resp.FromCache {
					cachedCount++
				}
			}
		}
	}

	avgDuration := time.Duration(0)
	if successCount > 0 {
		avgDuration = totalDuration / time.Duration(successCount)
	}

	successRate := float64(successCount) / float64(len(m.detailedResponses)) * 100

	// Fill in ping results
	m.reportData.PingResults = PingResults{
		Responses: m.detailedResponses,
		Summary: PingSummary{
			TotalPings:  len(m.detailedResponses),
			Successful:  successCount,
			Failed:      len(m.detailedResponses) - successCount,
			CachedHits:  cachedCount,
			AvgDuration: avgDuration,
			MinDuration: minDuration,
			MaxDuration: maxDuration,
			SuccessRate: successRate,
		},
	}

	// Calculate overall statistics
	totalDataTransferred := int64(0)
	for _, resp := range m.detailedResponses {
		totalDataTransferred += resp.ContentSize
	}
	
	requestsPerSecond := float64(len(m.detailedResponses)) / time.Since(m.startTime).Seconds()

	m.reportData.Statistics = Statistics{
		TotalDuration:     time.Since(m.startTime),
		AverageInterval:   m.interval,
		DataTransferred:   totalDataTransferred,
		RequestsPerSecond: requestsPerSecond,
	}

	// Collect comprehensive info data
	m.reportData.InfoData = collectAllInfoData(m.url)

	m.reportData.Generated = time.Now()

	// Set export status for TUI display
	var exportedFiles []string
	
	// Export to JSON if requested
	if m.exportJSON != "" {
		err := exportJSONReportTUI(m.reportData, m.exportJSON)
		if err == nil {
			exportedFiles = append(exportedFiles, "📊 JSON: "+m.exportJSON)
		}
	}

	// Export to HTML if requested
	if m.exportHTML != "" {
		err := exportHTMLReportTUI(m.reportData, m.exportHTML)
		if err == nil {
			exportedFiles = append(exportedFiles, "📈 HTML: "+m.exportHTML)
		}
	}
	
	// Update export status for TUI display
	if len(exportedFiles) > 0 {
		m.exportStatus = "✅ Reports exported:\n" + strings.Join(exportedFiles, "\n")
	}
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
		// Check if reports were exported and show file locations
		if (m.exportJSON != "" || m.exportHTML != "") && (m.count > 0 && m.current >= m.count) {
			var exportedFiles []string
			if m.exportJSON != "" {
				exportedFiles = append(exportedFiles, m.exportJSON)
			}
			if m.exportHTML != "" {
				exportedFiles = append(exportedFiles, m.exportHTML)
			}
			if len(exportedFiles) > 0 {
				if len(exportedFiles) == 1 {
					status = infoStyle.Render(fmt.Sprintf("✅ Completed - Report written to: %s", exportedFiles[0]))
				} else {
					status = infoStyle.Render(fmt.Sprintf("✅ Completed - Reports written to: %s", strings.Join(exportedFiles, ", ")))
				}
			} else {
				status = infoStyle.Render("✅ Completed")
			}
		} else {
			status = infoStyle.Render("✅ Completed")
		}
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
		status + "\n\n"
	
	// Add export status if reports were exported
	if m.exportStatus != "" {
		content += successStyle.Render(m.exportStatus) + "\n\n"
	}
	
	content += controls

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
		
		// Generate cache key
		authString := ""
		if m.authConfig.UseBasic {
			authString = m.authConfig.BasicAuth.Username + ":" + m.authConfig.BasicAuth.Password
		}
		if m.authConfig.UseCookie {
			authString += ":" + m.authConfig.CookieAuth
		}
		cacheKey := generateCacheKey(m.url, authString)
		
		var fromCache bool
		var body []byte
		var headers http.Header
		var contentType string
		var contentSize int64
		
		// Check cache first if enabled
		if m.useCache {
			if entry, found := globalCache.Get(cacheKey); found {
				duration := time.Since(start)
				fromCache = true
				headers = entry.Headers
				body = entry.Body
				contentSize = int64(len(body))
				if ct := headers.Get("Content-Type"); ct != "" {
					contentType = ct
				}
				
				// Create detailed response for reporting
				detailedResp := DetailedPingResponse{
					PingResponse: PingResponse{
						StatusCode: entry.StatusCode,
						Duration:   duration,
						Timestamp:  time.Now(),
					},
					Index:       m.current + 1,
					FromCache:   true,
					Headers:     headers,
					ContentType: contentType,
					ContentSize: contentSize,
				}
				
				return PingResultMsg{
					Response: PingResponse{
						StatusCode: entry.StatusCode,
						Duration:   duration,
						Timestamp:  time.Now(),
					},
					DetailedResponse: &detailedResp,
				}
			}
		}

		// Create request with authentication
		req, err := http.NewRequest("GET", m.url, nil)
		if err != nil {
			detailedResp := DetailedPingResponse{
				PingResponse: PingResponse{
					Error:     err,
					Duration:  time.Since(start),
					Timestamp: time.Now(),
				},
				Index:       m.current + 1,
				FromCache:   false,
			}
			
			return PingResultMsg{
				Response: PingResponse{
					Error:     err,
					Duration:  time.Since(start),
					Timestamp: time.Now(),
				},
				DetailedResponse: &detailedResp,
			}
		}

		// Configure authentication
		configureAuthentication(req, m.authConfig)

		// Perform request
		resp, err := m.client.Do(req)
		duration := time.Since(start)

		if err != nil {
			detailedResp := DetailedPingResponse{
				PingResponse: PingResponse{
					Error:     err,
					Duration:  duration,
					Timestamp: time.Now(),
				},
				Index:       m.current + 1,
				FromCache:   false,
			}
			
			return PingResultMsg{
				Response: PingResponse{
					Error:     err,
					Duration:  duration,
					Timestamp: time.Now(),
				},
				DetailedResponse: &detailedResp,
			}
		}

		statusCode := resp.StatusCode
		headers = resp.Header
		contentType = headers.Get("Content-Type")
		
		// Read body for caching and size calculation
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		contentSize = int64(len(body))
		
		// Cache the response if caching is enabled
		if m.useCache {
			entry := &CacheEntry{
				Response:   resp,
				Body:       body,
				Timestamp:  time.Now(),
				StatusCode: statusCode,
				Headers:    headers,
			}
			globalCache.Set(cacheKey, entry)
		}

		// Create detailed response for reporting
		detailedResp := DetailedPingResponse{
			PingResponse: PingResponse{
				StatusCode: statusCode,
				Duration:   duration,
				Timestamp:  time.Now(),
			},
			Index:       m.current + 1,
			FromCache:   fromCache,
			Headers:     headers,
			ContentType: contentType,
			ContentSize: contentSize,
		}

		return PingResultMsg{
			Response: PingResponse{
				StatusCode: statusCode,
				Duration:   duration,
				Timestamp:  time.Now(),
			},
			DetailedResponse: &detailedResp,
		}
	}
}

// collectAllInfoData collects comprehensive information about a URL
func collectAllInfoData(targetURL string) InfoData {
	infoData := InfoData{}
	
	// Extract host from URL
	host := extractHostFromURL(targetURL)
	
	// DNS Information
	start := time.Now()
	ns, err := net.LookupNS(host)
	dnsLookupTime := time.Since(start)
	
	if err != nil {
		infoData.DNS = DNSInfo{
			LookupTime: dnsLookupTime,
			Error:      err.Error(),
		}
	} else {
		nameservers := make([]string, len(ns))
		for i, server := range ns {
			nameservers[i] = server.Host
		}
		infoData.DNS = DNSInfo{
			Nameservers: nameservers,
			LookupTime:  dnsLookupTime,
		}
	}
	
	// IP Information
	start = time.Now()
	ips, err := net.LookupIP(host)
	ipLookupTime := time.Since(start)
	
	if err != nil {
		infoData.IP = IPInfo{
			LookupTime: ipLookupTime,
			Error:      err.Error(),
		}
	} else {
		var ipv4, ipv6, all []string
		for _, ip := range ips {
			all = append(all, ip.String())
			if ip.To4() != nil {
				ipv4 = append(ipv4, ip.String())
			} else {
				ipv6 = append(ipv6, ip.String())
			}
		}
		infoData.IP = IPInfo{
			Addresses:  all,
			IPv4:       ipv4,
			IPv6:       ipv6,
			LookupTime: ipLookupTime,
		}
	}
	
	// Certificate Information (only for HTTPS)
	if strings.HasPrefix(targetURL, "https://") || (!strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://")) {
		conn, err := tls.Dial("tcp", host+":443", nil)
		if err != nil {
			infoData.Certificate = CertificateInfo{
				Error: err.Error(),
			}
		} else {
			defer conn.Close()
			cert := conn.ConnectionState().PeerCertificates[0]
			now := time.Now()
			isValid := now.After(cert.NotBefore) && now.Before(cert.NotAfter)
			daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
			
			infoData.Certificate = CertificateInfo{
				Subject:         cert.Subject.String(),
				Issuer:          cert.Issuer.String(),
				NotBefore:       cert.NotBefore,
				NotAfter:        cert.NotAfter,
				IsValid:         isValid,
				DaysUntilExpiry: daysUntilExpiry,
				SignatureAlg:    cert.SignatureAlgorithm.String(),
			}
		}
	}
	
	// WHOIS Information
	start = time.Now()
	rootDomain := getRootDomain(host)
	whoisResult, err := whois.Whois(rootDomain)
	whoisLookupTime := time.Since(start)
	
	if err != nil {
		infoData.WHOIS = WHOISInfo{
			Domain:     rootDomain,
			LookupTime: whoisLookupTime,
			Error:      err.Error(),
		}
	} else {
		infoData.WHOIS = WHOISInfo{
			Domain:     rootDomain,
			RawData:    whoisResult,
			LookupTime: whoisLookupTime,
		}
	}
	
	// Resource Statistics
	if !hasProtocol(targetURL) {
		targetURL = "https://" + targetURL
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			infoData.Resources = collectResourceStats(string(body), targetURL)
		}
	}
	
	// Performance Metrics
	perfMetrics, err := collectPerformanceMetrics(targetURL, client)
	if err == nil {
		infoData.Performance = perfMetrics
	}
	
	// Geolocation Information
	if len(infoData.IP.Addresses) > 0 {
		geoData, err := fetchGeoLocation(infoData.IP.Addresses[0])
		if err == nil && geoData.Success {
			infoData.Geolocation = geoData
		}
	}
	
	return infoData
}

// exportJSONReport exports the report data as JSON
func exportJSONReport(reportData *ReportData, filename string) error {
	data, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON report: %v\n", err)
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON report: %v\n", err)
		return err
	}

	fmt.Printf("📊 JSON report exported to: %s\n", filename)
	return nil
}

// exportHTMLReport exports the report data as HTML
func exportHTMLReport(reportData *ReportData, filename string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatDuration": func(d time.Duration) string {
			if d == 0 {
				return "0s"
			}
			return d.String()
		},
		"formatBytes": func(b int64) string {
			if b == 0 {
				return "0 B"
			}
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
		},
		"statusText": func(code int) string {
			switch {
			case code >= 200 && code < 300:
				return "✅ OK"
			case code >= 300 && code < 400:
				return "🔄 Redirect"
			case code >= 400 && code < 500:
				return "🚫 Client Error"
			case code >= 500:
				return "💥 Server Error"
			default:
				return "❓ Unknown"
			}
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
	}).Parse(htmlReportTemplate)

	if err != nil {
		fmt.Printf("Error parsing HTML template: %v\n", err)
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, reportData)
	if err != nil {
		fmt.Printf("Error executing HTML template: %v\n", err)
		return err
	}

	err = os.WriteFile(filename, buf.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Error writing HTML report: %v\n", err)
		return err
	}

	fmt.Printf("📈 HTML report exported to: %s\n", filename)
	return nil
}

// exportJSONReportTUI exports the report data as JSON (TUI-compatible version)
func exportJSONReportTUI(reportData *ReportData, filename string) error {
	data, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// exportHTMLReportTUI exports the report data as HTML (TUI-compatible version)
func exportHTMLReportTUI(reportData *ReportData, filename string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatDuration": func(d time.Duration) string {
			if d == 0 {
				return "0s"
			}
			return d.String()
		},
		"formatSize": func(b int64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
		},
		"statusText": func(code int) string {
			switch {
			case code >= 200 && code < 300:
				return "✅ OK"
			case code >= 300 && code < 400:
				return "🔄 Redirect"
			case code >= 400 && code < 500:
				return "🚫 Client Error"
			case code >= 500:
				return "💥 Server Error"
			default:
				return "❓ Unknown"
			}
		},
	}).Parse(htmlReportTemplate)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, reportData)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

// htmlReportTemplate contains the HTML template for reports
const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>htping Report - {{.Target.URL}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .subtitle {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
            }
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h2 {
            margin-top: 0;
            color: #5a67d8;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: #f7fafc;
            border-radius: 8px;
        }
        .stat-value {
            font-size: 1.8em;
            font-weight: bold;
            color: #2d3748;
        }
        .stat-label {
            font-size: 0.9em;
            color: #718096;
            margin-top: 5px;
        }
        .ping-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .ping-table th,
        .ping-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        .ping-table th {
            background-color: #edf2f7;
            font-weight: 600;
        }
        .ping-table tr:hover {
            background-color: #f7fafc;
        }
        .status-ok { color: #38a169; }
        .status-redirect { color: #d69e2e; }
        .status-error { color: #e53e3e; }
        .cached { color: #805ad5; font-style: italic; }
        .meta-info {
            background: #2d3748;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
        }
        .meta-info h3 {
            margin-top: 0;
            color: #90cdf4;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .meta-item {
            display: flex;
            justify-content: space-between;
        }
        .full-width {
            grid-column: 1 / -1;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 htping Report</h1>
        <p class="subtitle">{{.Target.URL}} • Generated {{formatTime .Generated}}</p>
    </div>

    <div class="container">
        <div class="card">
            <h2>📊 Summary</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-value">{{.PingResults.Summary.TotalPings}}</div>
                    <div class="stat-label">Total Pings</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{.PingResults.Summary.Successful}}</div>
                    <div class="stat-label">Successful</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{printf "%.1f%%" .PingResults.Summary.SuccessRate}}</div>
                    <div class="stat-label">Success Rate</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{.PingResults.Summary.CachedHits}}</div>
                    <div class="stat-label">Cached Hits</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>⏱️ Performance</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-value">{{formatDuration .PingResults.Summary.AvgDuration}}</div>
                    <div class="stat-label">Average</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatDuration .PingResults.Summary.MinDuration}}</div>
                    <div class="stat-label">Minimum</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatDuration .PingResults.Summary.MaxDuration}}</div>
                    <div class="stat-label">Maximum</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{formatBytes .Statistics.DataTransferred}}</div>
                    <div class="stat-label">Data Transfer</div>
                </div>
            </div>
        </div>
    </div>

    {{if .InfoData.DNS.Nameservers}}
    <div class="card">
        <h2>🌐 DNS Information</h2>
        <div class="stat-item">
            <div class="stat-label">Lookup Time: {{formatDuration .InfoData.DNS.LookupTime}}</div>
        </div>
        <ul style="margin-top: 15px;">
            {{range .InfoData.DNS.Nameservers}}
            <li>{{.}}</li>
            {{end}}
        </ul>
    </div>
    {{end}}

    {{if .InfoData.IP.Addresses}}
    <div class="card">
        <h2>📍 IP Information</h2>
        <div class="stat-item">
            <div class="stat-label">Lookup Time: {{formatDuration .InfoData.IP.LookupTime}}</div>
        </div>
        <div style="margin-top: 15px;">
            {{if .InfoData.IP.IPv4}}<p><strong>IPv4:</strong> {{range $i, $ip := .InfoData.IP.IPv4}}{{if $i}}, {{end}}{{$ip}}{{end}}</p>{{end}}
            {{if .InfoData.IP.IPv6}}<p><strong>IPv6:</strong> {{range $i, $ip := .InfoData.IP.IPv6}}{{if $i}}, {{end}}{{$ip}}{{end}}</p>{{end}}
        </div>
    </div>
    {{end}}

    </div>

    {{if .InfoData.Certificate.Subject}}
    <div class="container">
    <div class="card">
        <h2>🔒 Certificate Information</h2>
        <div class="meta-grid">
            <div class="meta-item">
                <span>Valid:</span>
                <span>{{if .InfoData.Certificate.IsValid}}✅ Yes{{else}}❌ No{{end}}</span>
            </div>
            <div class="meta-item">
                <span>Days Until Expiry:</span>
                <span>{{.InfoData.Certificate.DaysUntilExpiry}}</span>
            </div>
        </div>
        <div style="margin-top: 15px; font-size: 0.9em;">
            <p><strong>Subject:</strong> {{.InfoData.Certificate.Subject}}</p>
            <p><strong>Issuer:</strong> {{.InfoData.Certificate.Issuer}}</p>
            <p><strong>Valid From:</strong> {{formatTime .InfoData.Certificate.NotBefore}}</p>
            <p><strong>Valid Until:</strong> {{formatTime .InfoData.Certificate.NotAfter}}</p>
            <p><strong>Signature Algorithm:</strong> {{.InfoData.Certificate.SignatureAlg}}</p>
        </div>
    </div>

    {{if .InfoData.Geolocation.Country}}
    <div class="card">
        <h2>🌍 Geolocation</h2>
        <div style="font-size: 0.9em;">
            <p><strong>Country:</strong> {{.InfoData.Geolocation.Country}} ({{.InfoData.Geolocation.CountryCode}})</p>
            <p><strong>Region:</strong> {{.InfoData.Geolocation.RegionName}} ({{.InfoData.Geolocation.Region}})</p>
            <p><strong>City:</strong> {{.InfoData.Geolocation.City}}</p>
            <p><strong>Coordinates:</strong> {{printf "%.4f, %.4f" .InfoData.Geolocation.Lat .InfoData.Geolocation.Lon}}</p>
            <p><strong>Timezone:</strong> {{.InfoData.Geolocation.Timezone}}</p>
            <p><strong>ISP:</strong> {{.InfoData.Geolocation.ISP}}</p>
            <p><strong>Organization:</strong> {{.InfoData.Geolocation.Org}}</p>
            {{if .InfoData.Geolocation.AS}}<p><strong>AS:</strong> {{.InfoData.Geolocation.AS}}</p>{{end}}
        </div>
    </div>
    {{end}}
    </div>
    {{end}}

    {{if .InfoData.Resources}}
    <div class="card full-width">
        <h2>📊 Resource Analysis</h2>
        <div class="stat-grid">
            <div class="stat-item">
                <div class="stat-value">{{.InfoData.Resources.TotalResources}}</div>
                <div class="stat-label">Total Resources</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{.InfoData.Resources.Images}}</div>
                <div class="stat-label">Images</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{.InfoData.Resources.Scripts}}</div>
                <div class="stat-label">Scripts</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{.InfoData.Resources.Stylesheets}}</div>
                <div class="stat-label">Stylesheets</div>
            </div>
        </div>
        {{if .InfoData.Resources.ExternalHosts}}
        <div style="margin-top: 20px;">
            <h3>External Hosts</h3>
            <ul>
                {{range $host, $count := .InfoData.Resources.ExternalHosts}}
                <li>{{$host}} ({{$count}} resources)</li>
                {{end}}
            </ul>
        </div>
        {{end}}
    </div>
    {{end}}

    {{if .InfoData.Performance}}
    <div class="card full-width">
        <h2>⚡ Performance Analysis</h2>
        <div class="stat-grid">
            <div class="stat-item">
                <div class="stat-value">{{formatDuration .InfoData.Performance.DNSLookup}}</div>
                <div class="stat-label">DNS Lookup</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{formatDuration .InfoData.Performance.TCPConnect}}</div>
                <div class="stat-label">TCP Connect</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{formatDuration .InfoData.Performance.TLSHandshake}}</div>
                <div class="stat-label">TLS Handshake</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{formatDuration .InfoData.Performance.FirstByteTime}}</div>
                <div class="stat-label">First Byte Time</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{formatDuration .InfoData.Performance.ContentTransfer}}</div>
                <div class="stat-label">Content Transfer</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{formatBytes .InfoData.Performance.ResponseSize}}</div>
                <div class="stat-label">Response Size</div>
            </div>
        </div>
    </div>
    {{end}}

    {{if .InfoData.WHOIS.Domain}}
    <div class="card full-width">
        <h2>📜 WHOIS Information</h2>
        <p><strong>Domain:</strong> {{.InfoData.WHOIS.Domain}}</p>
        <p><strong>Lookup Time:</strong> {{formatDuration .InfoData.WHOIS.LookupTime}}</p>
        {{if .InfoData.WHOIS.Error}}
        <p><strong>Error:</strong> <span class="status-error">{{.InfoData.WHOIS.Error}}</span></p>
        {{else}}
        <details style="margin-top: 15px;">
            <summary style="cursor: pointer; font-weight: bold;">Raw WHOIS Data</summary>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 10px; font-size: 0.85em; overflow-x: auto;">{{.InfoData.WHOIS.RawData}}</pre>
        </details>
        {{end}}
    </div>
    {{end}}

    <div class="card full-width">
        <h2>🏓 Ping Results</h2>
        <table class="ping-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Size</th>
                    <th>Content Type</th>
                    <th>Cache</th>
                </tr>
            </thead>
            <tbody>
                {{range .PingResults.Responses}}
                <tr>
                    <td>{{.Index}}</td>
                    <td>
                        {{if .Error}}
                            <span class="status-error">❌ Error</span>
                        {{else}}
                            <span class="{{if ge .StatusCode 500}}status-error{{else if ge .StatusCode 400}}status-error{{else if ge .StatusCode 300}}status-redirect{{else}}status-ok{{end}}">
                                {{.StatusCode}} {{statusText .StatusCode}}
                            </span>
                        {{end}}
                    </td>
                    <td>{{formatDuration .Duration}}</td>
                    <td>{{formatBytes .ContentSize}}</td>
                    <td>{{.ContentType}}</td>
                    <td>{{if .FromCache}}<span class="cached">💾 Cached</span>{{else}}🌐 Live{{end}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="meta-info">
        <h3>🔧 Configuration & Metadata</h3>
        <div class="meta-grid">
            <div class="meta-item">
                <span>Tool:</span>
                <span>{{.Metadata.Tool}} {{.Metadata.Version}}</span>
            </div>
            <div class="meta-item">
                <span>Protocol:</span>
                <span>{{.Target.Protocol}}</span>
            </div>
            <div class="meta-item">
                <span>Interval:</span>
                <span>{{.Target.Options.Interval}}</span>
            </div>
            <div class="meta-item">
                <span>Cache Enabled:</span>
                <span>{{if .Target.Options.UseCache}}✅ Yes{{else}}❌ No{{end}}</span>
            </div>
            {{if .Target.Authentication.Type}}
            <div class="meta-item">
                <span>Authentication:</span>
                <span>🔐 {{.Target.Authentication.Type}}</span>
            </div>
            {{end}}
            <div class="meta-item">
                <span>Total Duration:</span>
                <span>{{formatDuration .Statistics.TotalDuration}}</span>
            </div>
            <div class="meta-item">
                <span>Requests/Second:</span>
                <span>{{printf "%.2f" .Statistics.RequestsPerSecond}}</span>
            </div>
        </div>
    </div>
</body>
</html>`

func main() {
	var pingCount int
	var useHTTP bool
	var showHTMLFlag bool
	var outputFilename string
	var showResourceStats bool
	var showPerformanceMetrics bool
	var showGeolocation bool
	var basicUsername string
	var basicPassword string
	var cookieAuth string
	var useCache bool
	var pingInterval int
	var exportJSON string
	var exportHTML string

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

		// Setup authentication config
		authConfig := AuthConfig{
			UseBasic:  basicUsername != "",
			UseCookie: cookieAuth != "",
			BasicAuth: BasicAuthConfig{
				Username: basicUsername,
				Password: basicPassword,
			},
			CookieAuth: cookieAuth,
		}

		// Set default interval if not specified
		interval := time.Duration(pingInterval) * time.Second
		if interval <= 0 {
			interval = time.Second // Default to 1 second
		}

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
			authConfig: authConfig,
			useCache:   useCache,
			interval:   interval,
			exportJSON: exportJSON,
			exportHTML: exportHTML,
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
			runSimplePing(url, ip, client, pingCount, interval, authConfig, useCache, exportJSON, exportHTML)
		}

		if showHTMLFlag {
			// Show HTML content
			showHTML(url, outputFilename)
		}

		if showResourceStats {
			// Show resource statistics
			showResourceStatistics(url)
		}

		if showPerformanceMetrics {
			// Show performance metrics
			showPerformanceInfo(url)
		}

		if showGeolocation {
			// Show geolocation information
			showGeolocationInfo(url)
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
	pingCmd.Flags().BoolVar(&showResourceStats, "resourcestats", false, "Show page resource statistics after pings")
	pingCmd.Flags().BoolVar(&showPerformanceMetrics, "performance", false, "Show performance metrics after pings")
	pingCmd.Flags().BoolVar(&showGeolocation, "geolocation", false, "Show geolocation information after pings")
	pingCmd.Flags().StringVarP(&basicUsername, "username", "u", "", "Basic authentication username")
	pingCmd.Flags().StringVarP(&basicPassword, "password", "p", "", "Basic authentication password")
	pingCmd.Flags().StringVar(&cookieAuth, "cookie", "", "Cookie authentication string (e.g., 'session=abc123')")
	pingCmd.Flags().BoolVar(&useCache, "cache", false, "Enable response caching (5 minute TTL)")
	pingCmd.Flags().IntVarP(&pingInterval, "interval", "i", 1, "Ping interval in seconds")
	pingCmd.Flags().StringVar(&exportJSON, "export-json", "", "Export results to JSON file")
	pingCmd.Flags().StringVar(&exportHTML, "export-html", "", "Export results to HTML report")
	
	// Add the same flags to root command for default ping behavior
	rootCmd.Flags().IntVarP(&pingCount, "count", "c", 0, "Number of pings to perform (0 for continuous)")
	rootCmd.Flags().BoolVar(&useHTTP, "http", false, "Use HTTP instead of HTTPS")
	rootCmd.Flags().BoolVar(&showHTMLFlag, "html", false, "Show HTML content after pings")
	rootCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Output filename for HTML content - use with --html")
	rootCmd.Flags().BoolVar(&showResourceStats, "resourcestats", false, "Show page resource statistics after pings")
	rootCmd.Flags().BoolVar(&showPerformanceMetrics, "performance", false, "Show performance metrics after pings")
	rootCmd.Flags().BoolVar(&showGeolocation, "geolocation", false, "Show geolocation information after pings")
	rootCmd.Flags().StringVarP(&basicUsername, "username", "u", "", "Basic authentication username")
	rootCmd.Flags().StringVarP(&basicPassword, "password", "p", "", "Basic authentication password")
	rootCmd.Flags().StringVar(&cookieAuth, "cookie", "", "Cookie authentication string (e.g., 'session=abc123')")
	rootCmd.Flags().BoolVar(&useCache, "cache", false, "Enable response caching (5 minute TTL)")
	rootCmd.Flags().IntVarP(&pingInterval, "interval", "i", 1, "Ping interval in seconds")
	rootCmd.Flags().StringVar(&exportJSON, "export-json", "", "Export results to JSON file")
	rootCmd.Flags().StringVar(&exportHTML, "export-html", "", "Export results to HTML report")

	// Add the output flag to showHTMLCmd as well
	showHTMLCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Output filename for HTML content - use with --html or htping html <url>")

	// New commands for additional features
	resourcesCmd := &cobra.Command{
		Use:   "resources <url>",
		Short: "Show page resource statistics",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targetURL := args[0]
			if !hasProtocol(targetURL) {
				targetURL = "https://" + targetURL
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(targetURL)
			if err != nil {
				fmt.Printf("Error fetching page: %v\n", err)
				return
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Error reading page: %v\n", err)
				return
			}
			
			stats := collectResourceStats(string(body), targetURL)
			fmt.Printf("📊 Resource Statistics for %s:\n\n", targetURL)
			fmt.Printf("  Total Resources: %d\n", stats.TotalResources)
			fmt.Printf("  Images: %d\n", stats.Images)
			fmt.Printf("  Scripts: %d\n", stats.Scripts)
			fmt.Printf("  Stylesheets: %d\n", stats.Stylesheets)
			fmt.Printf("  Links: %d\n", stats.Links)
			fmt.Printf("  Content Length: %d bytes\n", stats.ContentLength)
			fmt.Printf("  External Hosts: %d\n", len(stats.ExternalHosts))
			
			if len(stats.ExternalHosts) > 0 {
				fmt.Printf("\nExternal Hosts:\n")
				for host, count := range stats.ExternalHosts {
					fmt.Printf("  • %s (%d resources)\n", host, count)
				}
			}
		},
	}

	perfCmd := &cobra.Command{
		Use:   "perf <url>",
		Short: "Show performance metrics",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targetURL := args[0]
			if !hasProtocol(targetURL) {
				targetURL = "https://" + targetURL
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			perfMetrics, err := collectPerformanceMetrics(targetURL, client)
			if err != nil {
				fmt.Printf("Error collecting metrics: %v\n", err)
				return
			}
			
			fmt.Printf("⚡ Performance Metrics for %s:\n\n", targetURL)
			fmt.Printf("  DNS Lookup: %v\n", perfMetrics.DNSLookup)
			fmt.Printf("  TCP Connect: %v\n", perfMetrics.TCPConnect)
			fmt.Printf("  TLS Handshake: %v\n", perfMetrics.TLSHandshake)
			fmt.Printf("  First Byte Time: %v\n", perfMetrics.FirstByteTime)
			fmt.Printf("  Content Transfer: %v\n", perfMetrics.ContentTransfer)
			fmt.Printf("  Response Size: %d bytes\n", perfMetrics.ResponseSize)
			fmt.Printf("  Protocol: %s\n", perfMetrics.Protocol)
			
			if perfMetrics.ServerProcess > 0 {
				fmt.Printf("  Server Process: %v\n", perfMetrics.ServerProcess)
			}
		},
	}

	geoCmd := &cobra.Command{
		Use:   "geo <url>",
		Short: "Show geolocation information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			domain := args[0]
			ips, err := net.LookupIP(domain)
			if err != nil {
				fmt.Printf("Error resolving IP: %v\n", err)
				return
			}
			if len(ips) == 0 {
				fmt.Printf("No IP addresses found for %s\n", domain)
				return
			}
			
			ip := ips[0].String()
			geoData, err := fetchGeoLocation(ip)
			if err != nil {
				fmt.Printf("Error fetching geolocation: %v\n", err)
				return
			}
			if !geoData.Success {
				fmt.Printf("Geolocation failed: %s\n", geoData.Message)
				return
			}
			
			fmt.Printf("🌍 Geolocation for %s (%s):\n\n", domain, ip)
			fmt.Printf("  Country: %s (%s)\n", geoData.Country, geoData.CountryCode)
			fmt.Printf("  Region: %s (%s)\n", geoData.RegionName, geoData.Region)
			fmt.Printf("  City: %s\n", geoData.City)
			fmt.Printf("  Coordinates: %.4f, %.4f\n", geoData.Lat, geoData.Lon)
			fmt.Printf("  Timezone: %s\n", geoData.Timezone)
			fmt.Printf("  ISP: %s\n", geoData.ISP)
			fmt.Printf("  Organization: %s\n", geoData.Org)
			
			if geoData.Zip != "" {
				fmt.Printf("  ZIP: %s\n", geoData.Zip)
			}
			if geoData.AS != "" {
				fmt.Printf("  AS: %s\n", geoData.AS)
			}
			if geoData.ASName != "" {
				fmt.Printf("  AS Name: %s\n", geoData.ASName)
			}
		},
	}

	infoCmd.AddCommand(dnsCmd, ipCmd, certCmd, whoisCmd, resourcesCmd, perfCmd, geoCmd)
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

// collectResourceStats analyzes HTML content for resource statistics
func collectResourceStats(htmlContent string, baseURL string) *ResourceStats {
	stats := &ResourceStats{
		ResourceTypes: make(map[string]int),
		ExternalHosts: make(map[string]int),
		ContentLength: int64(len(htmlContent)),
	}

	// Parse base URL
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return stats
	}

	// Count images
	imgRegex := regexp.MustCompile(`<img[^>]+src=["']([^"']+)["']`)
	imgMatches := imgRegex.FindAllStringSubmatch(htmlContent, -1)
	stats.Images = len(imgMatches)
	stats.TotalResources += stats.Images
	stats.ResourceTypes["images"] = stats.Images

	// Count scripts
	scriptRegex := regexp.MustCompile(`<script[^>]*src=["']([^"']+)["']|<script[^>]*>`)
	scriptMatches := scriptRegex.FindAllStringSubmatch(htmlContent, -1)
	stats.Scripts = len(scriptMatches)
	stats.TotalResources += stats.Scripts
	stats.ResourceTypes["scripts"] = stats.Scripts

	// Count stylesheets
	cssRegex := regexp.MustCompile(`<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']|<style[^>]*>`)
	cssMatches := cssRegex.FindAllStringSubmatch(htmlContent, -1)
	stats.Stylesheets = len(cssMatches)
	stats.TotalResources += stats.Stylesheets
	stats.ResourceTypes["stylesheets"] = stats.Stylesheets

	// Count links
	linkRegex := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["']`)
	linkMatches := linkRegex.FindAllStringSubmatch(htmlContent, -1)
	stats.Links = len(linkMatches)
	stats.TotalResources += stats.Links
	stats.ResourceTypes["links"] = stats.Links

	// Analyze external hosts from all resources
	allResources := append(imgMatches, scriptMatches...)
	allResources = append(allResources, cssMatches...)
	allResources = append(allResources, linkMatches...)

	for _, match := range allResources {
		if len(match) > 1 && match[1] != "" {
			resourceURL, err := url.Parse(match[1])
			if err != nil {
				continue
			}
			
			// Resolve relative URLs
			if !resourceURL.IsAbs() {
				resourceURL = parsedBase.ResolveReference(resourceURL)
			}
			
			// Check if external
			if resourceURL.Host != "" && resourceURL.Host != parsedBase.Host {
				stats.ExternalHosts[resourceURL.Host]++
			}
		}
	}

	stats.TotalSize = stats.ContentLength
	return stats
}

// collectPerformanceMetrics measures detailed timing metrics during HTTP request
func collectPerformanceMetrics(targetURL string, client *http.Client) (*PerformanceMetrics, error) {
	metrics := &PerformanceMetrics{}
	
	// Parse URL to get host
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Time DNS lookup
	dnsStart := time.Now()
	_, err = net.LookupIP(parsedURL.Hostname())
	if err != nil {
		return nil, err
	}
	metrics.DNSLookup = time.Since(dnsStart)

	// Time TCP connection
	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, err
	}
	metrics.TCPConnect = time.Since(tcpStart)

	// Time TLS handshake if HTTPS
	if parsedURL.Scheme == "https" {
		tlsStart := time.Now()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: parsedURL.Hostname()})
		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
			return nil, err
		}
		metrics.TLSHandshake = time.Since(tlsStart)
		conn = tlsConn
	}
	conn.Close()

	// Perform actual HTTP request with timing
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	requestStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	firstByteTime := time.Since(requestStart)
	metrics.FirstByteTime = firstByteTime

	// Read response body
	bodyStart := time.Now()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	metrics.ContentTransfer = time.Since(bodyStart)
	metrics.ResponseSize = int64(len(body))
	
	// Calculate server processing time (approximation)
	metrics.ServerProcess = firstByteTime - metrics.DNSLookup - metrics.TCPConnect - metrics.TLSHandshake
	
	metrics.Protocol = resp.Proto
	
	// Count redirects by checking history
	if client.CheckRedirect != nil {
		// This is a simplified approach - in practice you'd need to implement redirect tracking
		metrics.Redirects = 0
	}

	return metrics, nil
}

// fetchGeoLocation fetches geographical information for an IP address
func fetchGeoLocation(ipAddress string) (*GeoLocation, error) {
	// Using ip-api.com free service (no API key required)
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s", ipAddress)
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geolocation API returned status: %d", resp.StatusCode)
	}
	
	var geoData GeoLocation
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&geoData)
	if err != nil {
		return nil, err
	}
	
	// ip-api.com uses "success" field instead of a Success boolean
	// We need to map their response format to our struct
	if geoData.Country != "" {
		geoData.Success = true
	}
	
	return &geoData, nil
}

// enhancedHTTPRequest performs HTTP request with resource analysis and performance metrics
func enhancedHTTPRequest(targetURL string, client *http.Client) (*http.Response, *ResourceStats, *PerformanceMetrics, error) {
	// Collect performance metrics
	perfMetrics, err := collectPerformanceMetrics(targetURL, client)
	if err != nil {
		// If performance collection fails, continue with basic request
		resp, err := client.Get(targetURL)
		return resp, nil, nil, err
	}
	
	// Perform regular request for content analysis
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, nil, perfMetrics, err
	}
	
	// Read body for resource analysis
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, nil, perfMetrics, err
	}
	resp.Body.Close()
	
	// Analyze resources
	resourceStats := collectResourceStats(string(body), targetURL)
	
	// Create new response with fresh body reader
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	
	return resp, resourceStats, perfMetrics, nil
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
		options:        []string{"DNS Servers", "IP Addresses", "Certificate Info", "WHOIS Info", "Resource Stats", "Performance Metrics", "Geolocation", "---", "Start HTTP Ping"},
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
		case 4: // Resource Stats
			targetURL := m.url
			if !hasProtocol(targetURL) {
				targetURL = "https://" + targetURL
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(targetURL)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error fetching page: %v", err))
			} else {
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					result = errorStyle.Render(fmt.Sprintf("Error reading page: %v", err))
				} else {
					stats := collectResourceStats(string(body), targetURL)
					result = successStyle.Render("📊 Resource Statistics:") + "\n\n" +
						fmt.Sprintf("  • Total Resources: %d\n", stats.TotalResources) +
						fmt.Sprintf("  • Images: %d\n", stats.Images) +
						fmt.Sprintf("  • Scripts: %d\n", stats.Scripts) +
						fmt.Sprintf("  • Stylesheets: %d\n", stats.Stylesheets) +
						fmt.Sprintf("  • Links: %d\n", stats.Links) +
						fmt.Sprintf("  • Content Length: %d bytes\n", stats.ContentLength) +
						fmt.Sprintf("  • External Hosts: %d\n", len(stats.ExternalHosts))
					
					if len(stats.ExternalHosts) > 0 {
						result += "\n" + warningStyle.Render("External Hosts:") + "\n"
						for host, count := range stats.ExternalHosts {
							result += fmt.Sprintf("    • %s (%d resources)\n", host, count)
						}
					}
				}
			}
		case 5: // Performance Metrics
			targetURL := m.url
			if !hasProtocol(targetURL) {
				targetURL = "https://" + targetURL
			}
			
			client := &http.Client{Timeout: 10 * time.Second}
			perfMetrics, err := collectPerformanceMetrics(targetURL, client)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error collecting metrics: %v", err))
			} else {
				result = successStyle.Render("⚡ Performance Metrics:") + "\n\n" +
					fmt.Sprintf("  • DNS Lookup: %v\n", perfMetrics.DNSLookup) +
					fmt.Sprintf("  • TCP Connect: %v\n", perfMetrics.TCPConnect) +
					fmt.Sprintf("  • TLS Handshake: %v\n", perfMetrics.TLSHandshake) +
					fmt.Sprintf("  • First Byte Time: %v\n", perfMetrics.FirstByteTime) +
					fmt.Sprintf("  • Content Transfer: %v\n", perfMetrics.ContentTransfer) +
					fmt.Sprintf("  • Response Size: %d bytes\n", perfMetrics.ResponseSize) +
					fmt.Sprintf("  • Protocol: %s\n", perfMetrics.Protocol)
				
				if perfMetrics.ServerProcess > 0 {
					result += fmt.Sprintf("  • Server Process: %v\n", perfMetrics.ServerProcess)
				}
			}
		case 6: // Geolocation
			// First get IP address
			ips, err := net.LookupIP(m.url)
			if err != nil {
				result = errorStyle.Render(fmt.Sprintf("Error resolving IP: %v", err))
			} else if len(ips) == 0 {
				result = errorStyle.Render("No IP addresses found")
			} else {
				ip := ips[0].String()
				geoData, err := fetchGeoLocation(ip)
				if err != nil {
					result = errorStyle.Render(fmt.Sprintf("Error fetching geolocation: %v", err))
				} else if !geoData.Success {
					result = errorStyle.Render(fmt.Sprintf("Geolocation failed: %s", geoData.Message))
				} else {
					result = successStyle.Render(fmt.Sprintf("🌍 Geolocation for %s:", ip)) + "\n\n" +
						fmt.Sprintf("  • Country: %s (%s)\n", geoData.Country, geoData.CountryCode) +
						fmt.Sprintf("  • Region: %s (%s)\n", geoData.RegionName, geoData.Region) +
						fmt.Sprintf("  • City: %s\n", geoData.City) +
						fmt.Sprintf("  • Coordinates: %.4f, %.4f\n", geoData.Lat, geoData.Lon) +
						fmt.Sprintf("  • Timezone: %s\n", geoData.Timezone) +
						fmt.Sprintf("  • ISP: %s\n", geoData.ISP) +
						fmt.Sprintf("  • Organization: %s\n", geoData.Org)
					
					if geoData.Zip != "" {
						result += fmt.Sprintf("  • ZIP: %s\n", geoData.Zip)
					}
					if geoData.AS != "" {
						result += fmt.Sprintf("  • AS: %s\n", geoData.AS)
					}
					if geoData.ASName != "" {
						result += fmt.Sprintf("  • AS Name: %s\n", geoData.ASName)
					}
				}
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
func runSimplePing(url, ip string, client *http.Client, count int, interval time.Duration, authConfig AuthConfig, useCache bool, exportJSON, exportHTML string) {
	fmt.Printf("Http pinging %s [%s] (interval: %v)\n\n", url, ip, interval)

	var totalDuration time.Duration
	var successfulPings int
	var detailedResponses []DetailedPingResponse
	startTime := time.Now()

	for i := 0; i < count || count <= 0; i++ {
		start := time.Now()
		
		// Generate cache key
		authString := ""
		if authConfig.UseBasic {
			authString = authConfig.BasicAuth.Username + ":" + authConfig.BasicAuth.Password
		}
		if authConfig.UseCookie {
			authString += ":" + authConfig.CookieAuth
		}
		cacheKey := generateCacheKey(url, authString)
		
		var resp *http.Response
		var fromCache bool
		
		// Check cache first if enabled
		if useCache {
			if entry, found := globalCache.Get(cacheKey); found {
				duration := time.Since(start)
				fmt.Printf("Status: %d (cached), Time: %v\n", entry.StatusCode, duration)
				fromCache = true
				totalDuration += duration
				successfulPings++
				
				// Add detailed response for reporting
				detailedResp := DetailedPingResponse{
					PingResponse: PingResponse{
						StatusCode: entry.StatusCode,
						Duration:   duration,
						Timestamp:  time.Now(),
					},
					Index:       i + 1,
					FromCache:   true,
					Headers:     entry.Headers,
					ContentType: entry.Headers.Get("Content-Type"),
					ContentSize: int64(len(entry.Body)),
				}
				detailedResponses = append(detailedResponses, detailedResp)
			}
		}
		
		if !fromCache {
			// Create request with authentication
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				fmt.Printf("Error creating request: %v\n", err)
				// Add error response for reporting
				detailedResp := DetailedPingResponse{
					PingResponse: PingResponse{
						Error:     err,
						Duration:  time.Since(start),
						Timestamp: time.Now(),
					},
					Index:     i + 1,
					FromCache: false,
				}
				detailedResponses = append(detailedResponses, detailedResp)
				continue
			}

			// Configure authentication
			configureAuthentication(req, authConfig)

			// Perform request
			resp, err = client.Do(req)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				// Add error response for reporting
				duration := time.Since(start)
				detailedResp := DetailedPingResponse{
					PingResponse: PingResponse{
						Error:     err,
						Duration:  duration,
						Timestamp: time.Now(),
					},
					Index:     i + 1,
					FromCache: false,
				}
				detailedResponses = append(detailedResponses, detailedResp)
				if count > 0 && i >= count-1 {
					break
				}
				time.Sleep(interval)
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
			
			// Read body for caching and size calculation
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			// Cache the response if caching is enabled
			if useCache {
				entry := &CacheEntry{
					Response:   resp,
					Body:       body,
					Timestamp:  time.Now(),
					StatusCode: statusCode,
					Headers:    resp.Header,
				}
				globalCache.Set(cacheKey, entry)
			}
			
			// Add detailed response for reporting
			detailedResp := DetailedPingResponse{
				PingResponse: PingResponse{
					StatusCode: statusCode,
					Duration:   duration,
					Timestamp:  time.Now(),
				},
				Index:       i + 1,
				FromCache:   false,
				Headers:     resp.Header,
				ContentType: resp.Header.Get("Content-Type"),
				ContentSize: int64(len(body)),
			}
			detailedResponses = append(detailedResponses, detailedResp)
		}

		if count > 0 && i >= count-1 {
			break
		}
		time.Sleep(interval)
	}

	if successfulPings > 0 {
		avgDuration := totalDuration / time.Duration(successfulPings)
		fmt.Printf("\nAverage response time: %v\n", avgDuration)
		fmt.Printf("Total successful pings: %d\n", successfulPings)
	} else {
		fmt.Println("\nNo successful pings")
	}

	// Generate reports if export options are specified
	if (exportJSON != "" || exportHTML != "") && len(detailedResponses) > 0 {
		generateSimpleReport(url, detailedResponses, startTime, interval, authConfig, useCache, count, exportJSON, exportHTML)
	}
}

// generateSimpleReport generates a report for simple ping mode
func generateSimpleReport(targetURL string, detailedResponses []DetailedPingResponse, startTime time.Time, interval time.Duration, authConfig AuthConfig, useCache bool, count int, exportJSON, exportHTML string) {
	reportData := &ReportData{}

	// Fill in report metadata
	reportData.Metadata = ReportMetadata{
		Tool:       "htping",
		Version:    "1.0.0",
		Command:    fmt.Sprintf("htping %s", targetURL),
		Duration:   time.Since(startTime).String(),
		ReportType: "ping-report",
	}

	// Fill in target information
	parsedURL, _ := url.Parse(targetURL)
	authInfo := AuthInfo{}
	if authConfig.UseBasic {
		authInfo.Type = "basic"
		authInfo.Username = authConfig.BasicAuth.Username
		authInfo.HasPassword = authConfig.BasicAuth.Password != ""
	}
	if authConfig.UseCookie {
		if authInfo.Type != "" {
			authInfo.Type += "+cookie"
		} else {
			authInfo.Type = "cookie"
		}
		authInfo.HasCookie = true
	}

	reportData.Target = TargetInfo{
		URL:      targetURL,
		Host:     parsedURL.Host,
		Protocol: parsedURL.Scheme,
		Port:     parsedURL.Port(),
		Authentication: authInfo,
		Options: TargetOptions{
			Interval: interval.String(),
			Count:    count,
			UseCache: useCache,
			Timeout:  "10s",
		},
	}

	// Calculate ping statistics
	var minDuration, maxDuration time.Duration
	var totalDuration time.Duration
	successCount := 0
	cachedCount := 0
	
	if len(detailedResponses) > 0 {
		minDuration = time.Duration(1<<63 - 1) // Max duration
		for _, resp := range detailedResponses {
			if resp.Error == nil {
				successCount++
				totalDuration += resp.Duration
				if resp.Duration < minDuration {
					minDuration = resp.Duration
				}
				if resp.Duration > maxDuration {
					maxDuration = resp.Duration
				}
				if resp.FromCache {
					cachedCount++
				}
			}
		}
	}

	avgDuration := time.Duration(0)
	if successCount > 0 {
		avgDuration = totalDuration / time.Duration(successCount)
	}

	successRate := float64(successCount) / float64(len(detailedResponses)) * 100

	// Fill in ping results
	reportData.PingResults = PingResults{
		Responses: detailedResponses,
		Summary: PingSummary{
			TotalPings:  len(detailedResponses),
			Successful:  successCount,
			Failed:      len(detailedResponses) - successCount,
			CachedHits:  cachedCount,
			AvgDuration: avgDuration,
			MinDuration: minDuration,
			MaxDuration: maxDuration,
			SuccessRate: successRate,
		},
	}

	// Calculate overall statistics
	totalDataTransferred := int64(0)
	for _, resp := range detailedResponses {
		totalDataTransferred += resp.ContentSize
	}
	
	requestsPerSecond := float64(len(detailedResponses)) / time.Since(startTime).Seconds()

	reportData.Statistics = Statistics{
		TotalDuration:     time.Since(startTime),
		AverageInterval:   interval,
		DataTransferred:   totalDataTransferred,
		RequestsPerSecond: requestsPerSecond,
	}

	// Collect comprehensive info data
	reportData.InfoData = collectAllInfoData(targetURL)

	reportData.Generated = time.Now()

	// Show generating reports message
	if exportJSON != "" || exportHTML != "" {
		fmt.Printf("🔄 Generating reports...\n")
	}

	// Export to JSON if requested
	if exportJSON != "" {
		exportJSONReport(reportData, exportJSON)
	}

	// Export to HTML if requested
	if exportHTML != "" {
		exportHTMLReport(reportData, exportHTML)
	}

	// Show completion message
	if exportJSON != "" || exportHTML != "" {
		fmt.Printf("✅ Report generation completed!\n")
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
		"  htping google.com -i 2 --cache       # Ping every 2s with caching\n" +
		"  htping site.com -u user -p pass      # Basic authentication\n" +
		"  htping google.com -c 5 --export-json report.json  # Export to JSON\n" +
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
	fmt.Println("  htping info resources <url>     # Page resource statistics")
	fmt.Println("  htping info perf <url>          # Performance metrics")
	fmt.Println("  htping info geo <url>           # Geolocation information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  htping google.com")
	fmt.Println("  htping google.com -c 5")
	fmt.Println("  htping info github.com")
	fmt.Println("  htping info dns stackoverflow.com")
	fmt.Println("  htping info resources google.com")
	fmt.Println("  htping info perf github.com")
	fmt.Println("  htping info geo example.com")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c, --count int       Number of pings (0 for continuous)")
	fmt.Println("  -i, --interval int    Ping interval in seconds (default: 1)")
	fmt.Println("      --http            Use HTTP instead of HTTPS")
	fmt.Println("      --html            Show HTML content after pings")
	fmt.Println("  -o, --output string   Output filename for HTML content")
	fmt.Println("  -u, --username string Basic authentication username")
	fmt.Println("  -p, --password string Basic authentication password")
	fmt.Println("      --cookie string   Cookie authentication string")
	fmt.Println("      --cache           Enable response caching (5 minute TTL)")
	fmt.Println("      --export-json string Export results to JSON file")
	fmt.Println("      --export-html string Export results to HTML report")
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
		"  htping info resources <url>     # Page resource statistics",
		"  htping info perf <url>          # Performance metrics",
		"  htping info geo <url>           # Geolocation information",
		"",
		"EXAMPLES:",
		"  htping google.com               # Continuous ping",
		"  htping google.com -c 5          # Ping 5 times",
		"  htping google.com -i 3          # Ping every 3 seconds",
		"  htping google.com --http        # Use HTTP instead of HTTPS",
		"  htping google.com --cache       # Enable response caching",
		"  htping site.com -u user -p pass # Basic authentication",
		"  htping site.com --cookie \"session=abc123\" # Cookie auth",
		"  htping info github.com          # Interactive info menu",
		"  htping info dns stackoverflow.com # DNS lookup",
		"  htping info resources google.com # Page resource analysis",
		"  htping info perf github.com     # Performance timing metrics",
		"  htping info geo example.com     # Server geolocation",
		"  htping google.com --html -o page.html # Save HTML content",
		"  htping google.com -c 5 --export-json report.json # Export ping data to JSON",
		"  htping google.com -c 5 --export-html report.html # Export ping data to HTML report",
		"",
		"OPTIONS:",
		"  -c, --count int       Number of pings (0 for continuous)",
		"  -i, --interval int    Ping interval in seconds (default: 1)",
		"      --http            Use HTTP instead of HTTPS",
		"      --html            Show HTML content after pings",
		"  -o, --output string   Output filename for HTML content",
		"  -u, --username string Basic authentication username",
		"  -p, --password string Basic authentication password",
		"      --cookie string   Cookie authentication string",
		"      --cache           Enable response caching (5 minute TTL)",
		"      --export-json string Export results to JSON file",
		"      --export-html string Export results to HTML report",
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

// showResourceStatistics displays resource statistics for a URL
func showResourceStatistics(targetURL string) {
	if !hasProtocol(targetURL) {
		targetURL = "https://" + targetURL
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		fmt.Printf("\n📊 Error fetching page resources: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("\n📊 Error reading page: %v\n", err)
		return
	}
	
	stats := collectResourceStats(string(body), targetURL)
	fmt.Printf("\n📊 Resource Statistics for %s:\n", targetURL)
	fmt.Printf("  Total Resources: %d\n", stats.TotalResources)
	fmt.Printf("  Images: %d\n", stats.Images)
	fmt.Printf("  Scripts: %d\n", stats.Scripts)
	fmt.Printf("  Stylesheets: %d\n", stats.Stylesheets)
	fmt.Printf("  Links: %d\n", stats.Links)
	fmt.Printf("  Content Length: %d bytes\n", stats.ContentLength)
	fmt.Printf("  External Hosts: %d\n", len(stats.ExternalHosts))
	
	if len(stats.ExternalHosts) > 0 {
		fmt.Printf("\nExternal Hosts:\n")
		for host, count := range stats.ExternalHosts {
			fmt.Printf("  • %s (%d resources)\n", host, count)
		}
	}
	fmt.Println()
}

// showPerformanceInfo displays performance metrics for a URL
func showPerformanceInfo(targetURL string) {
	if !hasProtocol(targetURL) {
		targetURL = "https://" + targetURL
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	perfMetrics, err := collectPerformanceMetrics(targetURL, client)
	if err != nil {
		fmt.Printf("\n⚡ Error collecting performance metrics: %v\n", err)
		return
	}
	
	fmt.Printf("\n⚡ Performance Metrics for %s:\n", targetURL)
	fmt.Printf("  DNS Lookup: %v\n", perfMetrics.DNSLookup)
	fmt.Printf("  TCP Connect: %v\n", perfMetrics.TCPConnect)
	fmt.Printf("  TLS Handshake: %v\n", perfMetrics.TLSHandshake)
	fmt.Printf("  First Byte Time: %v\n", perfMetrics.FirstByteTime)
	fmt.Printf("  Content Transfer: %v\n", perfMetrics.ContentTransfer)
	fmt.Printf("  Response Size: %d bytes\n", perfMetrics.ResponseSize)
	fmt.Printf("  Protocol: %s\n", perfMetrics.Protocol)
	
	if perfMetrics.ServerProcess > 0 {
		fmt.Printf("  Server Process: %v\n", perfMetrics.ServerProcess)
	}
	fmt.Println()
}

// showGeolocationInfo displays geolocation information for a URL
func showGeolocationInfo(targetURL string) {
	domain := extractHostFromURL(targetURL)
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf("\n🌍 Error resolving IP for %s: %v\n", domain, err)
		return
	}
	if len(ips) == 0 {
		fmt.Printf("\n🌍 No IP addresses found for %s\n", domain)
		return
	}
	
	ip := ips[0].String()
	geoData, err := fetchGeoLocation(ip)
	if err != nil {
		fmt.Printf("\n🌍 Error fetching geolocation: %v\n", err)
		return
	}
	if !geoData.Success {
		fmt.Printf("\n🌍 Geolocation failed: %s\n", geoData.Message)
		return
	}
	
	fmt.Printf("\n🌍 Geolocation for %s (%s):\n", domain, ip)
	fmt.Printf("  Country: %s (%s)\n", geoData.Country, geoData.CountryCode)
	fmt.Printf("  Region: %s (%s)\n", geoData.RegionName, geoData.Region)
	fmt.Printf("  City: %s\n", geoData.City)
	fmt.Printf("  Coordinates: %.4f, %.4f\n", geoData.Lat, geoData.Lon)
	fmt.Printf("  Timezone: %s\n", geoData.Timezone)
	fmt.Printf("  ISP: %s\n", geoData.ISP)
	fmt.Printf("  Organization: %s\n", geoData.Org)
	
	if geoData.Zip != "" {
		fmt.Printf("  ZIP: %s\n", geoData.Zip)
	}
	if geoData.AS != "" {
		fmt.Printf("  AS: %s\n", geoData.AS)
	}
	if geoData.ASName != "" {
		fmt.Printf("  AS Name: %s\n", geoData.ASName)
	}
	fmt.Println()
}
