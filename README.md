# htping:
cli app to http/s ping web endpoints and get stats

## Usage

`htping ping`

Perform HTTP(S) ping to the URL

Usage:
  htping ping <url> [flags]

Flags:
  -c, --count int   Number of pings to perform (default 5)
  -h, --help        help for ping
      --http        Use HTTP instead of HTTPS

`htping info`


Get information about a URL options are 'whois', 'dns', 'cert info'

Usage:
  htping info [command]

Available Commands:
  cert        Show certificate details for HTTPS website
  dns         Show authoritative nameservers for the URL
  ip          Show IP addresses for the URL
  whois       Show WHOIS information for the URL

Flags:
  -h, --help   help for info

Use "htping info [command] --help" for more information about a command.

## Features:
* Authoritative dns server - done
* IP - done
* Cert details - done
* Time to fullfil request - done
* Stats on assets pulled - TODO
* With/without https - done
* Location - Needs an API key, might do if it's cheap
* Whois - done
* Add cookies as needed for auth - TBD
* Modify headers - TBD
* Basic auth support - TBD
* Crawl the page for more urls at start, allow filtering by regex, then start hitting those too and gathering stats - TBD
