# TOTP CLI

A secure command-line TOTP (Time-based One-Time Password) manager written in Go.

## Features

- Generate TOTP codes from secrets
- Store multiple TOTP secrets with labels
- AES-256-GCM encryption with master password
- Cross-platform (Windows, Linux, macOS)

## Installation

### Download Pre-built Binaries

Download the latest release from the [Releases](https://github.com/yourusername/totp-manager/releases) page.

### Build from Source
```bash
git clone https://github.com/yourusername/totp-manager.git
cd totp-manager
go build -o totp main.go
```

## Usage

### Command Line Mode
```bash
# Generate TOTP code with expiry information
./totp -token "JBSWY3DPEHPK3PXP"
# Output: 123456 valid until 12:34:56 (25 seconds)

# Silent mode (only output the code)
./totp -token "JBSWY3DPEHPK3PXP" -s
# Output: 123456
```

### Interactive Mode

Run without arguments for interactive menu:
```bash
./totp
```

Options:
1. **Add TOTP** - Save a new TOTP secret with a label
2. **Get TOTP** - Generate code for a saved TOTP
3. **List TOTPs** - Show all stored labels
4. **Delete TOTP** - Remove a TOTP entry
5. **Exit**

## Security

- All secrets are encrypted using AES-256-GCM
- Master password is used with PBKDF2 (100,000 iterations)
- Encrypted data stored in `totp_store.enc`
- File permissions set to 0600 (owner read/write only)

## Building for Different Platforms
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o totp-linux-amd64 main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o totp-macos-amd64 main.go
GOOS=darwin GOARCH=arm64 go build -o totp-macos-arm64 main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o totp-windows-amd64.exe main.go
```

## License

MIT License (or your preferred license)