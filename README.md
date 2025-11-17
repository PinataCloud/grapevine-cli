# Grapevine CLI

A fast, lightweight command-line interface for the Grapevine API built with Go.

## Project Structure

```
cli/
├── src/
│   ├── main.go       # Main CLI application
│   └── main_test.go  # Unit tests
├── go.mod            # Go module dependencies
└── README.md         # This file
```

## Development

### Prerequisites
- Go 1.21 or later

### Building

From the project root:

```bash
# Build for current platform
make build-cli

# Build for all platforms
make build-cli-all

# Or directly with Go (from cli directory):
cd cli
go build -o ../grapevine src/main.go
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