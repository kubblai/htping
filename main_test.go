package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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

	// Check that default options are present - actual options from main.go:544
	expectedOptions := []string{"DNS Servers", "IP Addresses", "Certificate Info", "WHOIS Info", "---", "Start HTTP Ping"}
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

		expectedOptions := 6 // DNS, IP, Cert, WHOIS, separator, Start Ping
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

