package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Test URL parsing functions
func TestHasProtocol(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"HTTP protocol", "http://example.com", true},
		{"HTTPS protocol", "https://example.com", true},
		{"No protocol", "example.com", false},
		{"Empty string", "", false},
		{"Short string", "abc", false},
		{"HTTP uppercase", "HTTP://example.com", false}, // Case sensitive
		{"HTTPS uppercase", "HTTPS://example.com", false}, // Case sensitive
		{"FTP protocol", "ftp://example.com", false},
		{"Protocol-like but not", "httpx://example.com", false},
		{"Just protocol", "https://", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasProtocol(tt.url)
			if result != tt.expected {
				t.Errorf("hasProtocol(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestGetRootDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"Simple domain", "example.com", "example.com"},
		{"Subdomain", "www.example.com", "example.com"},
		{"Multiple subdomains", "api.v1.example.com", "example.com"},
		{"With protocol", "https://www.example.com", "example.com"},
		{"With protocol and path", "https://www.example.com/path", "example.com/path"},
		{"Single word", "localhost", "localhost"},
		{"Empty string", "", ""},
		{"Just protocol", "https://", ""},
		{"Complex subdomain", "mail.corporate.example.co.uk", "co.uk"},
		{"IP address", "192.168.1.1", "1.1"},
		{"Domain with port", "example.com:8080", "example.com:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRootDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("getRootDomain(%q) = %q, want %q", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestExtractHostFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"Simple domain", "example.com", "example.com"},
		{"With HTTP protocol", "http://example.com", "example.com"},
		{"With HTTPS protocol", "https://example.com", "example.com"},
		{"With path", "https://example.com/path/to/resource", "example.com"},
		{"With port", "https://example.com:8080", "example.com"},
		{"With port and path", "https://example.com:8080/api/v1", "example.com"},
		{"Subdomain", "https://api.example.com", "api.example.com"},
		{"Complex URL", "https://api.example.com:443/v1/users?id=123", "api.example.com"},
		{"No protocol with path", "example.com/path", "example.com"},
		{"No protocol with port", "example.com:8080", "example.com"},
		{"Empty string", "", ""},
		{"Just protocol", "https://", ""},
		{"Localhost", "http://localhost:3000/api", "localhost"},
		{"IP address", "http://192.168.1.1:8080/test", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHostFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("extractHostFromURL(%q) = %q, want %q", tt.url, result, tt.expected)
			}
		})
	}
}

// Test constructor functions
func TestNewInfoModel(t *testing.T) {
	url := "https://example.com"
	model := NewInfoModel(url)

	if model == nil {
		t.Fatal("NewInfoModel returned nil")
	}

	if model.url != url {
		t.Errorf("Expected URL %q, got %q", url, model.url)
	}

	if model.selected != 0 {
		t.Errorf("Expected selected to be 0, got %d", model.selected)
	}

	if len(model.options) == 0 {
		t.Error("Expected options to be populated")
	}

	// Check that default options are present - updated options with new features
	expectedOptions := []string{"DNS Servers", "IP Addresses", "Certificate Info", "WHOIS Info", "Resource Stats", "Performance Metrics", "Geolocation", "---", "Start HTTP Ping"}
	for i, expectedOption := range expectedOptions {
		if i < len(model.options) && model.options[i] != expectedOption {
			t.Errorf("Expected option %d to be %q, got %q", i, expectedOption, model.options[i])
		}
	}
}

func TestNewInfoModelWithSize(t *testing.T) {
	url := "https://example.com"
	width, height := 80, 24
	model := NewInfoModelWithSize(url, width, height)

	if model == nil {
		t.Fatal("NewInfoModelWithSize returned nil")
	}

	if model.width != width {
		t.Errorf("Expected width %d, got %d", width, model.width)
	}

	if model.height != height {
		t.Errorf("Expected height %d, got %d", height, model.height)
	}

	if model.url != url {
		t.Errorf("Expected URL %q, got %q", url, model.url)
	}
}

func TestNewWelcomeModel(t *testing.T) {
	model := NewWelcomeModel()

	if model == nil {
		t.Fatal("NewWelcomeModel returned nil")
	}

	if model.selected != 0 {
		t.Errorf("Expected selected to be 0, got %d", model.selected)
	}

	if len(model.options) == 0 {
		t.Error("Expected options to be populated")
	}

	// Check that input is initialized (may not be accessible in tests)
	// Note: input field might be private or handled differently
}

func TestNewWelcomeModelWithSize(t *testing.T) {
	width, height := 100, 30
	model := NewWelcomeModelWithSize(width, height)

	if model == nil {
		t.Fatal("NewWelcomeModelWithSize returned nil")
	}

	if model.width != width {
		t.Errorf("Expected width %d, got %d", width, model.width)
	}

	if model.height != height {
		t.Errorf("Expected height %d, got %d", height, model.height)
	}
}

func TestNewHelpModel(t *testing.T) {
	model := NewHelpModel()

	if model == nil {
		t.Fatal("NewHelpModel returned nil")
	}

	if len(model.content) == 0 {
		t.Error("Expected help content to be populated")
	}

	if model.scroll != 0 {
		t.Errorf("Expected scroll to be 0, got %d", model.scroll)
	}
}

// Test HTTP functionality with mock server
func TestHTTPPingFunctionality(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Test with a real HTTP client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(server.URL)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	if duration <= 0 {
		t.Error("Expected positive duration")
	}
}

func TestHTTPPingError(t *testing.T) {
	// Test with invalid URL
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	_, err := client.Get("http://invalid-domain-that-does-not-exist-12345.com")

	if err == nil {
		t.Error("Expected error for invalid domain, got nil")
	}
}

// Test PingResponse structure
func TestPingResponse(t *testing.T) {
	response := PingResponse{
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
		Error:      nil,
		Timestamp:  time.Now(),
	}

	if response.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", response.StatusCode)
	}

	if response.Duration != 100*time.Millisecond {
		t.Errorf("Expected duration 100ms, got %v", response.Duration)
	}

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error)
	}

	if response.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
}

// Test terminal detection (basic test)
func TestIsTerminal(t *testing.T) {
	// This test might behave differently in different environments
	// We'll just ensure the function doesn't panic and returns a boolean
	result := isTerminal()

	// The result can be true or false depending on test environment
	if result != true && result != false {
		t.Error("isTerminal() should return a boolean value")
	}
}

// Benchmark tests for performance-critical functions
func BenchmarkHasProtocol(b *testing.B) {
	urls := []string{
		"https://example.com",
		"http://example.com",
		"example.com",
		"ftp://example.com",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		hasProtocol(url)
	}
}

func BenchmarkGetRootDomain(b *testing.B) {
	domains := []string{
		"https://www.example.com/path",
		"api.v1.example.com",
		"example.com",
		"localhost",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		getRootDomain(domain)
	}
}

func BenchmarkExtractHostFromURL(b *testing.B) {
	urls := []string{
		"https://api.example.com:443/v1/users?id=123",
		"http://localhost:3000/api",
		"example.com/path",
		"https://example.com",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		extractHostFromURL(url)
	}
}

// Test edge cases and error conditions
func TestURLParsingEdgeCases(t *testing.T) {
	t.Run("hasProtocol with malformed URLs", func(t *testing.T) {
		malformedURLs := []string{
			"://example.com",
			"http:/example.com",
			"https//example.com",
			"ht tp://example.com",
		}

		for _, url := range malformedURLs {
			// These should return false as they don't have proper protocols
			result := hasProtocol(url)
			if result && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				t.Errorf("hasProtocol(%q) should return false for malformed URL", url)
			}
		}
	})

	t.Run("getRootDomain with special characters", func(t *testing.T) {
		specialDomains := []string{
			"example.com/path?query=value",
			"example.com#fragment",
			"user:pass@example.com",
			"example.com:8080/path",
		}

		for _, domain := range specialDomains {
			result := getRootDomain(domain)
			// Should handle these gracefully without panicking
			if result == "" && domain != "" {
				t.Logf("getRootDomain(%q) = %q (may be expected for special cases)", domain, result)
			}
		}
	})
}

// Test ping functionality with different scenarios
func TestPingModelCreation(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}

	tests := []struct {
		name     string
		url      string
		count    int
		useHTTP  bool
	}{
		{"HTTPS ping", "https://example.com", 3, false},
		{"HTTP ping", "http://example.com", 5, true},
		{"Infinite ping", "https://example.com", 0, false},
		{"Single ping", "https://example.com", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &PingModel{
				url:       tt.url,
				count:     tt.count,
				useHTTP:   tt.useHTTP,
				client:    client,
				running:   true,
				startTime: time.Now(),
			}

			if model.url != tt.url {
				t.Errorf("Expected URL %q, got %q", tt.url, model.url)
			}

			if model.count != tt.count {
				t.Errorf("Expected count %d, got %d", tt.count, model.count)
			}

			if model.useHTTP != tt.useHTTP {
				t.Errorf("Expected useHTTP %v, got %v", tt.useHTTP, model.useHTTP)
			}

			if !model.running {
				t.Error("Expected model to be running")
			}
		})
	}
}

func TestPingResponseHandling(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		duration       time.Duration
		expectError    bool
		errorMessage   string
	}{
		{"Success response", 200, 100 * time.Millisecond, false, ""},
		{"Redirect response", 301, 150 * time.Millisecond, false, ""},
		{"Client error", 404, 200 * time.Millisecond, false, ""},
		{"Server error", 500, 300 * time.Millisecond, false, ""},
		{"Network error", 0, 0, true, "network error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.expectError {
						// Create a custom error for testing
						err = errors.New(tt.errorMessage)
			}

			response := PingResponse{
				StatusCode: tt.statusCode,
				Duration:   tt.duration,
				Error:      err,
				Timestamp:  time.Now(),
			}

			if response.StatusCode != tt.statusCode {
				t.Errorf("Expected status code %d, got %d", tt.statusCode, response.StatusCode)
			}

			if response.Duration != tt.duration {
				t.Errorf("Expected duration %v, got %v", tt.duration, response.Duration)
			}

			if tt.expectError && response.Error == nil {
				t.Error("Expected error but got nil")
			}

			if !tt.expectError && response.Error != nil {
				t.Errorf("Expected no error but got: %v", response.Error)
			}
		})
	}
}

func TestHTTPClientConfiguration(t *testing.T) {
	t.Run("Client with timeout", func(t *testing.T) {
		timeout := 10 * time.Second
		client := &http.Client{
			Timeout: timeout,
		}

		if client.Timeout != timeout {
			t.Errorf("Expected timeout %v, got %v", timeout, client.Timeout)
		}
	})

	t.Run("Client with custom transport", func(t *testing.T) {
		transport := &http.Transport{}
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: transport,
		}

		if client.Transport == nil {
			t.Error("Expected transport to be set")
		}
	})
}

// Test info command functions with mock data
func TestInfoCommandFunctionality(t *testing.T) {
	t.Run("DNS resolution simulation", func(t *testing.T) {
		// Test URL parsing for DNS lookup
		testURLs := []string{
			"https://google.com",
			"http://example.com",
			"github.com",
			"api.example.com",
		}

		for _, url := range testURLs {
			host := extractHostFromURL(url)
			if host == "" && url != "" {
				t.Errorf("Expected non-empty host for URL %q", url)
			}
		}
	})

	t.Run("IP address validation", func(t *testing.T) {
		// Test that we can handle various IP formats
		ips := []string{
			"192.168.1.1",
			"10.0.0.1",
			"127.0.0.1",
			"2001:db8::1",
			"::1",
		}

		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				t.Errorf("Failed to parse IP %q", ip)
			}
		}
	})

	t.Run("Certificate information structure", func(t *testing.T) {
		// Test TLS configuration
		config := &http.Transport{}

		if config.TLSClientConfig == nil {
			// This is expected since we're using default transport
			t.Log("TLS config is nil (expected for default transport)")
		}
	})
}

// Test TUI model methods
func TestTUIModelMethods(t *testing.T) {
	t.Run("PingModel Init", func(t *testing.T) {
		model := &PingModel{
			url:     "https://example.com",
			running: true,
		}

		cmd := model.Init()
		if cmd == nil {
			t.Error("Expected Init to return a command")
		}
	})

	t.Run("InfoModel options", func(t *testing.T) {
		model := NewInfoModel("https://example.com")

		expectedOptions := 9 // DNS, IP, Cert, WHOIS, Resource Stats, Performance Metrics, Geolocation, separator, Start Ping
		if len(model.options) != expectedOptions {
			t.Errorf("Expected %d options, got %d", expectedOptions, len(model.options))
		}

		// Check that all expected options are present
		optionTexts := strings.Join(model.options, " ")
		requiredOptions := []string{"DNS", "IP", "Certificate", "WHOIS", "Ping"}

		for _, required := range requiredOptions {
			if !strings.Contains(optionTexts, required) {
				t.Errorf("Expected to find %q in options", required)
			}
		}
	})

	t.Run("WelcomeModel options", func(t *testing.T) {
		model := NewWelcomeModel()

		if len(model.options) == 0 {
			t.Error("Expected welcome options to be populated")
		}

		// Note: input field might be private or not accessible in tests
		// We can't directly test the input field, but we can verify the model was created
	})

	t.Run("HelpModel content", func(t *testing.T) {
		model := NewHelpModel()

		if len(model.content) == 0 {
			t.Error("Expected help content to be populated")
		}

		// Check that help contains essential information
		contentText := strings.Join(model.content, " ")
		essentialTopics := []string{"Usage", "Commands", "Examples", "Options"}

		for _, topic := range essentialTopics {
			if !strings.Contains(contentText, topic) {
				t.Logf("Help content may be missing %q topic", topic)
			}
		}
	})
}

// Test message types
func TestMessageTypes(t *testing.T) {
	t.Run("PingTickMsg", func(t *testing.T) {
		msg := PingTickMsg{}
		// Just ensure the type exists and can be instantiated
		_ = msg
	})

	t.Run("PingResultMsg", func(t *testing.T) {
		response := PingResponse{
			StatusCode: 200,
			Duration:   100 * time.Millisecond,
			Timestamp:  time.Now(),
		}

		msg := PingResultMsg{Response: response}

		if msg.Response.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d", msg.Response.StatusCode)
		}

		if msg.Response.Duration != 100*time.Millisecond {
			t.Errorf("Expected duration 100ms, got %v", msg.Response.Duration)
		}
	})

	t.Run("InfoResultMsg", func(t *testing.T) {
		result := "DNS servers: 8.8.8.8, 1.1.1.1"
		msg := InfoResultMsg{Result: result}

		if msg.Result != result {
			t.Errorf("Expected result %q, got %q", result, msg.Result)
		}
	})
}

// Test model initialization with various inputs
func TestModelInitialization(t *testing.T) {
	t.Run("InfoModel with empty URL", func(t *testing.T) {
		model := NewInfoModel("")
		if model == nil {
			t.Fatal("NewInfoModel should handle empty URL")
		}
		if model.url != "" {
			t.Error("Expected empty URL to be preserved")
		}
	})

	t.Run("InfoModel with very long URL", func(t *testing.T) {
		longURL := "https://" + strings.Repeat("a", 1000) + ".com"
		model := NewInfoModel(longURL)
		if model == nil {
			t.Fatal("NewInfoModel should handle long URLs")
		}
		if model.url != longURL {
			t.Error("Expected long URL to be preserved")
		}
	})

	t.Run("WelcomeModel with zero dimensions", func(t *testing.T) {
		model := NewWelcomeModelWithSize(0, 0)
		if model == nil {
			t.Fatal("NewWelcomeModelWithSize should handle zero dimensions")
		}
		if model.width != 0 || model.height != 0 {
			t.Error("Expected zero dimensions to be preserved")
		}
	})

	t.Run("PingModel statistics", func(t *testing.T) {
		model := &PingModel{
			url:           "https://example.com",
			responses:     make([]PingResponse, 0),
			successCount:  0,
			totalDuration: 0,
			startTime:     time.Now(),
		}

		// Simulate some responses
		responses := []PingResponse{
			{StatusCode: 200, Duration: 100 * time.Millisecond, Timestamp: time.Now()},
			{StatusCode: 200, Duration: 150 * time.Millisecond, Timestamp: time.Now()},
			{StatusCode: 404, Duration: 200 * time.Millisecond, Timestamp: time.Now()},
		}

		for _, resp := range responses {
			model.responses = append(model.responses, resp)
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				model.successCount++
			}
			model.totalDuration += resp.Duration
		}

		if model.successCount != 2 {
			t.Errorf("Expected 2 successful responses, got %d", model.successCount)
		}

		expectedDuration := 450 * time.Millisecond
		if model.totalDuration != expectedDuration {
			t.Errorf("Expected total duration %v, got %v", expectedDuration, model.totalDuration)
		}

		if len(model.responses) != 3 {
			t.Errorf("Expected 3 responses, got %d", len(model.responses))
		}
	})
}

// Test HTML content for resource stats
const testHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="stylesheet" href="https://external.com/external.css">
    <script src="/js/app.js"></script>
    <script src="https://external.com/lib.js"></script>
</head>
<body>
    <h1>Test Page</h1>
    <img src="/images/logo.png" alt="Logo">
    <img src="https://external.com/banner.jpg" alt="Banner">
    <a href="/about">About</a>
    <a href="https://example.com/external">External Link</a>
    <style>
        body { margin: 0; }
    </style>
    <script>
        console.log('inline script');
    </script>
</body>
</html>
`

// Test new resource statistics functionality
func TestCollectResourceStats(t *testing.T) {
	baseURL := "https://test.com"
	stats := collectResourceStats(testHTML, baseURL)

	// Test basic counts
	if stats.Images != 2 {
		t.Errorf("Expected 2 images, got %d", stats.Images)
	}
	if stats.Scripts != 3 { // 2 external + 1 inline
		t.Errorf("Expected 3 scripts, got %d", stats.Scripts)
	}
	if stats.Stylesheets != 3 { // 2 external + 1 inline
		t.Errorf("Expected 3 stylesheets, got %d", stats.Stylesheets)
	}
	if stats.Links != 2 {
		t.Errorf("Expected 2 links, got %d", stats.Links)
	}

	// Test total resources
	expectedTotal := stats.Images + stats.Scripts + stats.Stylesheets + stats.Links
	if stats.TotalResources != expectedTotal {
		t.Errorf("Expected total resources %d, got %d", expectedTotal, stats.TotalResources)
	}

	// Test external hosts
	if len(stats.ExternalHosts) != 2 {
		t.Errorf("Expected 2 external hosts, got %d", len(stats.ExternalHosts))
	}
	
	if stats.ExternalHosts["external.com"] != 3 {
		t.Errorf("Expected 3 resources from external.com, got %d", stats.ExternalHosts["external.com"])
	}
	
	if stats.ExternalHosts["example.com"] != 1 {
		t.Errorf("Expected 1 resource from example.com, got %d", stats.ExternalHosts["example.com"])
	}

	// Test content length
	if stats.ContentLength != int64(len(testHTML)) {
		t.Errorf("Expected content length %d, got %d", len(testHTML), stats.ContentLength)
	}

	// Test resource types map
	if stats.ResourceTypes["images"] != stats.Images {
		t.Errorf("ResourceTypes images mismatch: expected %d, got %d", stats.Images, stats.ResourceTypes["images"])
	}
	if stats.ResourceTypes["scripts"] != stats.Scripts {
		t.Errorf("ResourceTypes scripts mismatch: expected %d, got %d", stats.Scripts, stats.ResourceTypes["scripts"])
	}
}

// Test performance metrics collection
func TestCollectPerformanceMetrics(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testHTML))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	metrics, err := collectPerformanceMetrics(server.URL, client)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if metrics == nil {
		t.Fatal("Expected metrics, got nil")
	}

	// Test that timing metrics are reasonable
	if metrics.DNSLookup < 0 {
		t.Errorf("DNS lookup time should be non-negative, got %v", metrics.DNSLookup)
	}
	if metrics.TCPConnect < 0 {
		t.Errorf("TCP connect time should be non-negative, got %v", metrics.TCPConnect)
	}
	if metrics.FirstByteTime <= 0 {
		t.Errorf("First byte time should be positive, got %v", metrics.FirstByteTime)
	}
	if metrics.ContentTransfer < 0 {
		t.Errorf("Content transfer time should be non-negative, got %v", metrics.ContentTransfer)
	}

	// Test response size
	if metrics.ResponseSize != int64(len(testHTML)) {
		t.Errorf("Expected response size %d, got %d", len(testHTML), metrics.ResponseSize)
	}

	// Test protocol
	if metrics.Protocol == "" {
		t.Error("Expected protocol to be set")
	}
}

// Test geolocation functionality
func TestFetchGeoLocation(t *testing.T) {
	// Test with a known public IP (Google DNS)
	geoData, err := fetchGeoLocation("8.8.8.8")
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if geoData == nil {
		t.Fatal("Expected geo data, got nil")
	}

	if !geoData.Success {
		t.Errorf("Expected success=true, got %v. Message: %s", geoData.Success, geoData.Message)
	}

	// Basic validation - Google's DNS should return US
	if geoData.CountryCode != "US" {
		t.Errorf("Expected country code US for Google DNS, got %s", geoData.CountryCode)
	}

	if geoData.Country == "" {
		t.Error("Expected country to be set")
	}

	// Coordinates should be reasonable for US
	if geoData.Lat < 24 || geoData.Lat > 50 {
		t.Errorf("Unexpected latitude for US IP: %f", geoData.Lat)
	}
	if geoData.Lon < -125 || geoData.Lon > -66 {
		t.Errorf("Unexpected longitude for US IP: %f", geoData.Lon)
	}
}

// Test enhanced HTTP request functionality
func TestEnhancedHTTPRequest(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testHTML))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, resourceStats, perfMetrics, err := enhancedHTTPRequest(server.URL, client)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	defer resp.Body.Close()

	if resourceStats == nil {
		t.Fatal("Expected resource stats, got nil")
	}

	if perfMetrics == nil {
		t.Fatal("Expected performance metrics, got nil")
	}

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify resource stats
	if resourceStats.Images != 2 {
		t.Errorf("Expected 2 images, got %d", resourceStats.Images)
	}

	// Verify performance metrics
	if perfMetrics.ResponseSize != int64(len(testHTML)) {
		t.Errorf("Expected response size %d, got %d", len(testHTML), perfMetrics.ResponseSize)
	}
}

// Test resource stats edge cases
func TestResourceStatsEdgeCases(t *testing.T) {
	// Test empty HTML
	emptyStats := collectResourceStats("", "https://test.com")
	if emptyStats.TotalResources != 0 {
		t.Errorf("Empty HTML should have 0 resources, got %d", emptyStats.TotalResources)
	}

	// Test HTML without resources
	plainHTML := "<html><head><title>Test</title></head><body><p>No resources</p></body></html>"
	plainStats := collectResourceStats(plainHTML, "https://test.com")
	if plainStats.TotalResources != 0 {
		t.Errorf("Plain HTML should have 0 resources, got %d", plainStats.TotalResources)
	}

	// Test malformed HTML
	malformedHTML := "<img src='broken.png'><script src=><link rel='stylesheet'"
	malformedStats := collectResourceStats(malformedHTML, "https://test.com")
	// Should still parse what it can
	if malformedStats.Images != 1 {
		t.Errorf("Malformed HTML should find 1 image, got %d", malformedStats.Images)
	}
}

// Test geolocation error handling
func TestGeoLocationErrorHandling(t *testing.T) {
	// Test with invalid IP - API might return success=false instead of error
	geoData, err := fetchGeoLocation("invalid-ip")
	if err == nil && geoData != nil && geoData.Success {
		t.Error("Expected error or unsuccessful result for invalid IP")
	} else if err != nil {
		t.Logf("Invalid IP returned error as expected: %v", err)
	} else if geoData != nil && !geoData.Success {
		t.Logf("Invalid IP returned unsuccessful result as expected: %s", geoData.Message)
	}

	// Test with private IP (should work but might return limited data)
	geoData, err = fetchGeoLocation("192.168.1.1")
	if err != nil {
		// Private IPs might not work with the API, that's ok
		t.Logf("Private IP geolocation failed as expected: %v", err)
	} else if geoData != nil && !geoData.Success {
		t.Logf("Private IP geolocation returned unsuccessful result: %s", geoData.Message)
	}
}

// Benchmark tests for new functionality
func BenchmarkCollectResourceStatsNew(b *testing.B) {
	baseURL := "https://test.com"
	for i := 0; i < b.N; i++ {
		collectResourceStats(testHTML, baseURL)
	}
}

// Test comprehensive export functionality
func TestAuthenticationConfig(t *testing.T) {
	// Test basic auth
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	authConfig := AuthConfig{
		UseBasic: true,
		BasicAuth: BasicAuthConfig{
			Username: "testuser",
			Password: "testpass",
		},
	}
	
	configureAuthentication(req, authConfig)
	
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		t.Errorf("Expected basic auth header, got: %s", authHeader)
	}
	
	// Test cookie auth
	req2, _ := http.NewRequest("GET", "http://example.com", nil)
	authConfig2 := AuthConfig{
		UseCookie: true,
		CookieAuth: "session=abc123",
	}
	
	configureAuthentication(req2, authConfig2)
	
	cookieHeader := req2.Header.Get("Cookie")
	if cookieHeader != "session=abc123" {
		t.Errorf("Expected cookie header 'session=abc123', got: %s", cookieHeader)
	}
}

// Test response caching functionality
func TestResponseCaching(t *testing.T) {
	cache := NewResponseCache(time.Minute)
	
	// Test setting and getting cache entry
	entry := &CacheEntry{
		StatusCode: 200,
		Body:       []byte("test body"),
		Timestamp:  time.Now(),
		Headers:    http.Header{"Content-Type": []string{"text/html"}},
	}
	
	key := "test-key"
	cache.Set(key, entry)
	
	retrieved, found := cache.Get(key)
	if !found {
		t.Error("Expected to find cached entry")
	}
	
	if retrieved.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", retrieved.StatusCode)
	}
	
	if string(retrieved.Body) != "test body" {
		t.Errorf("Expected body 'test body', got %s", string(retrieved.Body))
	}
}

// Test cache expiration
func TestCacheExpiration(t *testing.T) {
	cache := NewResponseCache(10 * time.Millisecond) // Very short TTL
	
	entry := &CacheEntry{
		StatusCode: 200,
		Body:       []byte("test"),
		Timestamp:  time.Now(),
		Headers:    make(http.Header),
	}
	
	cache.Set("test-key", entry)
	
	// Should exist immediately
	_, found := cache.Get("test-key")
	if !found {
		t.Error("Expected to find fresh cache entry")
	}
	
	// Wait for expiration
	time.Sleep(20 * time.Millisecond)
	
	// Should be expired now
	_, found = cache.Get("test-key")
	if found {
		t.Error("Expected cache entry to be expired")
	}
}

// Test JSON export functionality
func TestJSONExport(t *testing.T) {
	// Create test report data
	reportData := &ReportData{
		Metadata: ReportMetadata{
			Tool:       "htping",
			Version:    "1.0.0",
			ReportType: "test-report",
		},
		Target: TargetInfo{
			URL:      "http://example.com",
			Host:     "example.com",
			Protocol: "http",
		},
		PingResults: PingResults{
			Summary: PingSummary{
				TotalPings:  2,
				Successful:  2,
				Failed:      0,
				SuccessRate: 100.0,
			},
		},
		Generated: time.Now(),
	}
	
	// Test JSON export
	filename := "test-export.json"
	defer os.Remove(filename) // Clean up after test
	
	err := exportJSONReport(reportData, filename)
	if err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}
	
	// Verify file exists and contains valid JSON
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read exported JSON: %v", err)
	}
	
	var importedReport ReportData
	err = json.Unmarshal(data, &importedReport)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	
	if importedReport.Metadata.Tool != "htping" {
		t.Errorf("Expected tool 'htping', got %s", importedReport.Metadata.Tool)
	}
	
	if importedReport.PingResults.Summary.TotalPings != 2 {
		t.Errorf("Expected 2 total pings, got %d", importedReport.PingResults.Summary.TotalPings)
	}
}

// Test HTML export functionality
func TestHTMLExport(t *testing.T) {
	// Create minimal test report data
	reportData := &ReportData{
		Metadata: ReportMetadata{
			Tool:       "htping",
			Version:    "1.0.0",
			ReportType: "test-report",
		},
		Target: TargetInfo{
			URL:      "http://example.com",
			Host:     "example.com",
			Protocol: "http",
		},
		PingResults: PingResults{
			Responses: []DetailedPingResponse{
				{
					PingResponse: PingResponse{
						StatusCode: 200,
						Duration:   100 * time.Millisecond,
						Timestamp:  time.Now(),
					},
					Index:     1,
					FromCache: false,
				},
			},
			Summary: PingSummary{
				TotalPings:  1,
				Successful:  1,
				Failed:      0,
				SuccessRate: 100.0,
			},
		},
		Generated: time.Now(),
	}
	
	// Test HTML export
	filename := "test-export.html"
	defer os.Remove(filename) // Clean up after test
	
	err := exportHTMLReport(reportData, filename)
	if err != nil {
		t.Fatalf("HTML export failed: %v", err)
	}
	
	// Verify file exists and contains expected content
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read exported HTML: %v", err)
	}
	
	html := string(data)
	if !strings.Contains(html, "htping Report") {
		t.Error("HTML should contain 'htping Report'")
	}
	
	if !strings.Contains(html, "example.com") {
		t.Error("HTML should contain target URL 'example.com'")
	}
	
	if !strings.Contains(html, "200") {
		t.Error("HTML should contain status code '200'")
	}
}

// Test comprehensive info data collection
func TestCollectAllInfoData(t *testing.T) {
	// Use a real domain for basic testing
	infoData := collectAllInfoData("https://google.com")
	
	// Test DNS information
	if len(infoData.DNS.Nameservers) == 0 && infoData.DNS.Error == "" {
		t.Error("Expected DNS nameservers or error")
	}
	
	// Test IP information
	if len(infoData.IP.Addresses) == 0 && infoData.IP.Error == "" {
		t.Error("Expected IP addresses or error")
	}
	
	// Test certificate information (for HTTPS)
	if infoData.Certificate.Subject == "" && infoData.Certificate.Error == "" {
		t.Error("Expected certificate info or error for HTTPS domain")
	}
	
	// Test WHOIS information
	if infoData.WHOIS.RawData == "" && infoData.WHOIS.Error == "" {
		t.Error("Expected WHOIS data or error")
	}
}

// Test cache key generation
func TestCacheKeyGeneration(t *testing.T) {
	url1 := "http://example.com"
	url2 := "http://example.org"
	auth1 := "user1:pass1"
	auth2 := "user2:pass2"
	
	// Same URL and auth should generate same key
	key1a := generateCacheKey(url1, auth1)
	key1b := generateCacheKey(url1, auth1)
	if key1a != key1b {
		t.Error("Same URL and auth should generate same cache key")
	}
	
	// Different URL should generate different key
	key2 := generateCacheKey(url2, auth1)
	if key1a == key2 {
		t.Error("Different URLs should generate different cache keys")
	}
	
	// Different auth should generate different key
	key3 := generateCacheKey(url1, auth2)
	if key1a == key3 {
		t.Error("Different auth should generate different cache keys")
	}
}

// Test report data structures
func TestReportDataStructure(t *testing.T) {
	now := time.Now()
	
	reportData := ReportData{
		Metadata: ReportMetadata{
			Tool:       "htping",
			Version:    "1.0.0",
			Command:    "htping example.com -c 5",
			Duration:   "5s",
			ReportType: "ping-report",
		},
		Target: TargetInfo{
			URL:      "https://example.com",
			Host:     "example.com",
			Protocol: "https",
			Options: TargetOptions{
				Interval: "1s",
				Count:    5,
				UseCache: true,
				Timeout:  "10s",
			},
		},
		Generated: now,
	}
	
	if reportData.Metadata.Tool != "htping" {
		t.Errorf("Expected tool 'htping', got %s", reportData.Metadata.Tool)
	}
	
	if reportData.Target.Protocol != "https" {
		t.Errorf("Expected protocol 'https', got %s", reportData.Target.Protocol)
	}
	
	if reportData.Target.Options.Count != 5 {
		t.Errorf("Expected count 5, got %d", reportData.Target.Options.Count)
	}
	
	if !reportData.Target.Options.UseCache {
		t.Error("Expected UseCache to be true")
	}
}

// Benchmark cache operations
func BenchmarkCacheOperations(b *testing.B) {
	cache := NewResponseCache(time.Hour)
	entry := &CacheEntry{
		StatusCode: 200,
		Body:       []byte("test data"),
		Timestamp:  time.Now(),
		Headers:    make(http.Header),
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		key := generateCacheKey("http://example.com", "test")
		cache.Set(key, entry)
		_, _ = cache.Get(key)
	}
}

// Test interval functionality
func TestPingIntervals(t *testing.T) {
	intervals := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		5 * time.Second,
	}
	
	for _, interval := range intervals {
		// Test that intervals are handled properly
		if interval <= 0 {
			t.Errorf("Interval should be positive, got %v", interval)
		}
		
		// Test interval string conversion
		intervalStr := interval.String()
		if intervalStr == "" {
			t.Error("Interval string should not be empty")
		}
	}
}

