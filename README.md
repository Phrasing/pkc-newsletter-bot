# pkc

<img src="Gemini_Generated_Image_2vqt8w2vqt8w2vqt.png" width="400" alt="pkc">

A high-performance concurrent email registration tool with proxy rotation and bot protection bypass capabilities.

## Features

- Concurrent worker pool with configurable parallelism
- Automatic proxy rotation
- Bot protection bypass
- CAPTCHA solving integration
- Graceful error handling and shutdown

## Requirements

- Go 1.21+
- Valid CAPTCHA solver API key (2Captcha or CapSolver)
- HTTP proxies

## Setup

1. Clone the repository

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Create a `.env` file with your API keys:
   ```
   HYPER_API_KEY=your_hyper_api_key
   2CAP_KEY=your_2captcha_api_key
   ```

4. Create a `proxies.txt` file with one proxy per line:
   ```
   # Supported formats:
   ip:port:username:password
   ip:port
   http://username:password@ip:port
   ```

## Usage

### Generate emails with a catchall domain:
```bash
./pkc <catchall-domain> <target-count> <worker-count>

# Example: Register 500 emails using 100 workers
./pkc example.com 500 100
```

### Use emails from a file:
```bash
./pkc <target-count> <worker-count>

# Example: Process 500 emails from emails.txt using 100 workers
./pkc 500 100
```

When no catchall domain is provided, the program reads emails from `emails.txt` (one email per line).

## Building

### Development build:
```bash
go build -o pkc .
```

### Production build (with embedded API keys):
```bash
./build.sh
```

## Files

| File | Description |
|------|-------------|
| `proxies.txt` | Proxy list (required) |
| `emails.txt` | Email list (optional, used when no catchall provided) |
| `.env` | API keys configuration |
| `engine.log` | Runtime/scheduler logs |
| `pkc.log` | Module-specific logs |

## License

Private use only.
