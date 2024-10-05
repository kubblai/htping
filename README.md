# htping:
cli app to http/s ping web endpoints and get stats or some info.

## Usage

`htping ping`__

Perform HTTP(S) ping to the URL

Usage:__
  htping ping <url> [flags]__

Flags:__
-c, --count int   Number of pings to perform (default 5)__
-h, --help        help for ping__
    --http        Use HTTP instead of HTTPS__

`htping info`__

Get information about a URL options are 'whois', 'dns', 'cert info'__

Usage:__
  htping info [command]__

Available Commands:__
  cert        Show certificate details for HTTPS website__
  dns         Show authoritative nameservers for the URL__
  ip          Show IP addresses for the URL__
  whois       Show WHOIS information for the URL__

Flags:__
  -h, --help   help for info__

Use "htping info [command] --help" for more information about a command.__

### Features:
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
