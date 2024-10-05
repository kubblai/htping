package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/likexian/whois"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "htping"}

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Get information about a URL options are 'whois', 'dns', 'cert info'",
	}

	var dnsCmd = &cobra.Command{
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

	var ipCmd = &cobra.Command{
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

	var certCmd = &cobra.Command{
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

	var whoisCmd = &cobra.Command{
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

	var pingCount int
	var useHTTP bool
	var pingCmd = &cobra.Command{
		Use:   "ping <url>",
		Short: "Perform HTTP(S) ping to the URL",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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

			fmt.Printf("Http pinging %s [%s]\n\n", url, ip)

			var totalDuration time.Duration
			var successfulPings int

			for i := 0; i < pingCount; i++ {
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
				var statusOk string = "OK"
				var statusColor *color.Color
				switch {
				case statusCode >= 200 && statusCode < 300:
					statusColor = color.New(color.FgGreen)
					statusOk = "Status OK"
				case statusCode >= 300 && statusCode < 400:
					statusColor = color.New(color.FgYellow)
					statusOk = "Some redirect"
				case statusCode >= 400 && statusCode < 500:
					statusColor = color.New(color.FgRed)
					statusOk = "Auth Error"
				case statusCode >= 500:
					statusColor = color.New(color.FgBlue)
					statusOk = "Server Error"
				default:
					statusColor = color.New(color.FgWhite)
					statusOk = "Unknown"
				}

				statusColor.Printf("Status code: %v, %v, Time: %v\n", statusCode, statusOk, totalDuration)
				resp.Body.Close()

				time.Sleep(1 * time.Second) // Wait 1 second between pings
			}

			if successfulPings > 0 {
				avgDuration := totalDuration / time.Duration(successfulPings)
				fmt.Printf("\nAverage response time: %v from %v\n", avgDuration, url)
			} else {
				fmt.Println("\nNo successful pings")
			}
		},
	}

	// Initialize flags
	pingCmd.Flags().IntVarP(&pingCount, "count", "c", 5, "Number of pings to perform")
	pingCmd.Flags().BoolVar(&useHTTP, "http", false, "Use HTTP instead of HTTPS")

	infoCmd.AddCommand(dnsCmd, ipCmd, certCmd, whoisCmd)
	rootCmd.AddCommand(infoCmd, pingCmd)

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
