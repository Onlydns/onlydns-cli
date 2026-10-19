# @onlydns/cli

Official Command-Line Interface (CLI) for the **OnlyDNS System API** ([onlydns.com](https://www.onlydns.com)).

Fast, type-safe, and zero-bloat tool for human developers and autonomous AI agents to manage DNS zones, DNS records, DNSSEC signing, and TSIG keys directly from the terminal or scripts.

---

## Installation

### Global Installation (Recommended)

```bash
npm install -g @onlydns/cli
```

Or using Yarn / pnpm / Bun:

```bash
pnpm add -g @onlydns/cli
bun add -g @onlydns/cli
```

### Instant Execution via `npx` / `bunx`

Run commands instantly without global installation:

```bash
npx @onlydns/cli domains list
bunx @onlydns/cli records find example.com --name api
```

---

## Authentication & Configuration

The CLI resolves API tokens using the following priority order:

1. `--api-key` / `-k` CLI argument
2. `ONLYDNS_API_KEY` or `ONLYDNS_API_TOKEN` environment variable
3. Stored configuration in `~/.config/onlydns/config.json` (or `$XDG_CONFIG_HOME/onlydns/config.json`)

### Storing Your API Key

```bash
# Save your API token securely to ~/.config/onlydns/config.json (file mode 0600)
onlydns config login <YOUR_API_KEY>

# Check current authentication status
onlydns config show

# View configuration file path
onlydns config path

# Clear stored credentials
onlydns config clear
```

### Using Environment Variables

```bash
export ONLYDNS_API_KEY="your_api_token_here"
onlydns domains list
```

---

## Quick Reference & Commands

### 1. Domains

```bash
# List all domains
onlydns domains list

# List with pagination
onlydns domains list --offset 0 --limit 50

# Create a new domain zone
onlydns domains create example.com
```

### 2. DNS Records

```bash
# List all records for a domain
onlydns records list example.com

# Find records with substring / pattern filtering (requires --name, --type, or --value)
onlydns records find example.com --name api
onlydns records find example.com --type A
onlydns records find example.com --value 192.0.2
onlydns records find example.com --name mail --type A --value 192.0.2.25

# Add / Append DNS record values (merges into existing record if present)
onlydns records add example.com --name www --type A --value 192.0.2.1 --ttl 300
onlydns records add example.com --name @ --type TXT --value "v=spf1 include:example.com ~all"

# Add multiple values
onlydns records add example.com --name api --type A --value 192.0.2.1 --value 192.0.2.2

# Update / Replace all values for a record
onlydns records update example.com --name www --type A --value 192.0.2.100 --ttl 600

# Remove a specific value from a multi-value record
onlydns records remove example.com --name api --type A --value 192.0.2.1

# Remove an entire record
onlydns records remove example.com --name www --type A
```

### 3. DNSSEC

```bash
# Inspect DNSSEC status and DS keys
onlydns dnssec status example.com

# Enable DNSSEC signing
onlydns dnssec enable example.com

# Disable DNSSEC signing
onlydns dnssec disable example.com
```

### 4. TSIG Keys

```bash
# List all account TSIG keys
onlydns tsig list

# Generate a new TSIG key (algorithms: hmac-sha256, hmac-sha512, etc.)
onlydns tsig create --algo hmac-sha256 --name ns1-key

# Retrieve a specific TSIG key
onlydns tsig get ns1-key

# Configure TSIG permissions for zone transfers (AXFR) and Dynamic DNS Updates
onlydns tsig set-permissions example.com ns1-key --transfer --update

# Clear all TSIG permissions for a domain
onlydns tsig clear example.com
```

---

## Global Options & JSON Output

All commands support JSON formatting for programmatic consumption by scripts and AI agent pipelines:

```bash
# Output full JSON response
onlydns --json records list example.com
onlydns --json domains list

# Custom API endpoint / Timeout
onlydns --base-url https://api.onlydns.com/v1 --timeout 15 domains list
```

| Flag | Shorthand | Description |
| :--- | :--- | :--- |
| `--api-key` | `-k` | API token (overrides environment and stored config) |
| `--base-url` | | Custom API base URL |
| `--json` | | Output responses in structured JSON |
| `--timeout` | | HTTP request timeout in seconds (default: 30) |
| `--help` | `-h` | Display help and usage instructions |
| `--version` | `-V` | Show version number |

---

## Programmatic Usage

You can also import and invoke the CLI programmatically within TypeScript/JavaScript tools:

```typescript
import { runCli } from '@onlydns/cli';

const exitCode = await runCli(['records', 'list', 'example.com', '--json']);
```

---

## License

MIT License. Developed for [OnlyDNS](https://www.onlydns.com).
