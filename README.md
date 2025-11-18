# Grapevine CLI

A fast, lightweight command-line interface for the Grapevine API built with Go.

## Installation

### Via npm (Recommended)
```bash
npm install -g @pinata/grapevine-cli
```

### From Source
```bash
git clone https://github.com/PinataCloud/grapevine-cli
cd grapevine-cli
make build
```

## Quick Start

1. **Set up authentication:**
   ```bash
   # Login with your private key
   grapevine auth login --alias my-account --key YOUR_PRIVATE_KEY
   
   # Or set environment variable
   export PRIVATE_KEY="your-private-key-here"
   ```

2. **Create your first feed:**
   ```bash
   grapevine feed create "My Feed" --description "My first content feed"
   ```

3. **Add content to your feed:**
   ```bash
   grapevine entry add FEED_ID "Hello world!" --title "My first entry"
   ```

## Usage

### Global Options
- `--network` - Network to use: `testnet` (default) or `mainnet`
- `--key` - Private key (or use `PRIVATE_KEY` env var)  
- `--debug` - Enable debug output

### Authentication

```bash
# Login with account alias
grapevine auth login --alias my-account --key YOUR_PRIVATE_KEY

# Check authentication status
grapevine auth status

# List all accounts
grapevine auth list

# Logout
grapevine auth logout my-account
```

### Feed Management

```bash
# Create a new feed
grapevine feed create "Feed Name" --description "Description"

# List your feeds
grapevine feed myfeeds

# List all public feeds
grapevine feed list --limit 10

# Get specific feed
grapevine feed get FEED_ID

# Update feed
grapevine feed update FEED_ID --name "New Name" --description "New description"

# Delete feed
grapevine feed delete FEED_ID --force
```

### Entry Management

```bash
# Add content to feed (free to view)
grapevine entry add FEED_ID "Content here" --title "Entry Title"

# Add paid content (costs to view)
grapevine entry add FEED_ID "Premium content" --title "Premium Entry" --paid --price 100000

# List entries in a feed
grapevine entry list FEED_ID --limit 5

# Get specific entry
grapevine entry get FEED_ID ENTRY_ID

# Batch add entries from JSON file
grapevine entry batch FEED_ID entries.json

# Delete entry
grapevine entry delete FEED_ID ENTRY_ID --force
```

### Wallet Operations

```bash
# Show wallet address
grapevine wallet address

# Check wallet balance
grapevine wallet balance

# Show wallet info
grapevine wallet info
```

### Other Commands

```bash
# List available categories
grapevine categories

# Show CLI version
grapevine version

# Show network and SDK info
grapevine info

# Get help
grapevine --help
grapevine [command] --help
```

## Examples

### Creating a Content Feed
```bash
# Set up authentication
export PRIVATE_KEY="0x..."

# Create feed
FEED_ID=$(grapevine feed create "Tech News" --description "Latest tech updates" | grep -o 'Feed created: [0-9a-f-]*' | cut -d' ' -f3)

# Add free content
grapevine entry add $FEED_ID "Breaking: New JavaScript framework released!" --title "JS Framework News"

# Add premium content  
grapevine entry add $FEED_ID "Detailed analysis of the framework..." --title "In-Depth Analysis" --paid --price 50000

echo "Feed created with ID: $FEED_ID"
```

### Batch Content Upload
Create `entries.json`:
```json
[
  {"content": "First batch entry", "title": "Entry 1"},
  {"content": "Second batch entry", "title": "Entry 2"},
  {"content": "Third batch entry", "title": "Entry 3"}
]
```

Upload:
```bash
grapevine entry batch FEED_ID entries.json --delay 100
```

## Project Structure

```
grapevine-cli/
├── src/
│   ├── main.go       # Main CLI application
│   └── main_test.go  # Unit tests
├── bin/
│   └── grapevine     # Binary placeholder (replaced during npm install)
├── go.mod            # Go module dependencies
├── package.json      # npm package configuration
├── install.js        # npm installation script
├── Makefile          # Build commands
└── README.md         # This file
```

## Development

### Prerequisites
- Go 1.21 or later

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Or directly with Go:
go build -o grapevine src/main.go
```

### Testing

#### Unit Tests
```bash
# Run Go unit tests
make test
```

#### Integration Tests
Integration tests require a private key and make real API calls:

```bash
# Set your private key (for testnet testing)
export PRIVATE_KEY="your-private-key-here"

# Build the CLI
make build

# Run integration tests
./test/integration.sh
```

**Note**: Integration tests will:
- Create/delete feeds and entries on testnet
- Test all CLI commands end-to-end  
- Require a funded testnet wallet
- Take 30-60 seconds to complete

### Dependencies

The CLI uses these Go packages:
- `github.com/spf13/cobra` - Command-line interface framework
- `github.com/spf13/viper` - Configuration management
- `github.com/ethereum/go-ethereum` - Ethereum utilities for wallet operations

### Architecture

The CLI is built as a single Go binary with the following key components:

1. **Command Structure**: Uses Cobra for command hierarchy and flag parsing
2. **HTTP Client**: Custom client for Grapevine API interactions
3. **Authentication**: Ethereum wallet integration for signing API requests
4. **Configuration**: JSON-based config file management
5. **Cross-compilation**: Builds native binaries for all major platforms

### Performance Characteristics

- **Binary size**: ~8-15MB (optimized with `-ldflags "-s -w"`)
- **Startup time**: <100ms
- **Memory usage**: ~10-20MB runtime
- **Dependencies**: Zero runtime dependencies (static binary)

## Release Process

Binaries are built for:
- Linux (x64)
- macOS (x64 and ARM64)
- Windows (x64)

The build process creates optimized, stripped binaries for maximum performance and minimal size.