# Node Health Check & Failover

Automated service health monitoring and DNS failover script for high-availability infrastructure. Monitors primary and mirror servers, automatically updating Cloudflare DNS records when failures are detected.

## Features

- 🔄 Automatic failover between primary and mirror servers
- 🌐 IPv4 and IPv6 support
- 🏥 Multiple health check types (HTTP, Intel API, Threats API)
- ⏱️ Configurable cooldown periods to prevent DNS flapping
- 🔒 Lock file mechanism for manual intervention
- 📢 Discord notifications on failover events
- 🧪 Dry-run mode for safe testing

## Prerequisites

- Python 3.8+
- Cloudflare account with API access
- DNS records managed by Cloudflare

## Installation

1. Clone the repository:
```bash
git clone https://github.com/patrickbeane/node-health.git
cd node-health
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Copy the example environment file and configure:
```bash
cp .env.example .env
nano .env  # Add your credentials
```

4. Make the script executable:
```bash
chmod +x health_check.py
```

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Cloudflare API credentials
CF_API_TOKEN=your_cloudflare_api_token
CF_ZONE_ID=your_cloudflare_zone_id

# Discord webhook (optional but recommended)
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

### Service Configuration

Edit `health_check.py` and modify the `SERVICES` dictionary:

```python
SERVICES = {
    "your-service": {
        "dns_name": "service.example.com",
        "primary": {
            "url": "https://primary.example.com/health",
            "ip": "1.2.3.4",
            "ipv6": "2001:db8::1",  # Optional
            "check": "http"  # or "intel", "threats"
        },
        "mirror": {
            "url": "https://mirror.example.com/health",
            "ip": "5.6.7.8",
            "ipv6": "2001:db8::2",  # Optional
            "check": "http"
        }
    }
}
```

### Health Check Types

- **`http`**: Simple HTTP 200 status check (recommended for most services)
- **`intel`**: Custom check for intelligence/ban-list APIs
  - Validates JSON response with `total_bans` (integer > 0) and `top_countries` (non-empty array)
  - Originally built for threat intelligence feeds (over time)
  - Can be adapted for similar statistical APIs
- **`threats`**: Custom check for threat-feed APIs
  - Validates JSON with `generated_at` timestamp and `threats` array
  - Ensures data freshness (default: < 20 minutes old)
  - Each threat must have `ip` and `confidence` fields
  - Originally built for real-time threat intelligence feeds

**Note:** The `intel` and `threats` check types were designed for specific real-world APIs. For most use cases, stick with `http`. If you need custom validation logic for your API, these serve as examples you can extend in the `check_health()` function.

### Tunable Parameters

```python
STALE_THRESHOLD = timedelta(minutes=20)     # Max age for threats data
HTTP_TIMEOUT = 2                            # Health check timeout
CF_TIMEOUT = 10                             # Cloudflare API timeout
DNS_TTL = 60                                # DNS record TTL
MIN_SWITCH_INTERVAL = timedelta(minutes=5)  # Cooldown between switches
```

## Usage

### Manual Execution

```bash
# Normal run
./health_check.py

# Dry-run mode (no changes made)
./health_check.py --dry-run

# Verbose logging
./health_check.py -v

# Combine options
./health_check.py --dry-run -v
```

### Automated Health Checks

Run every minute:

```bash
crontab -e
```

Add:
```
* * * * * /path/to/health_check.py >> /var/log/node-health.log 2>&1
```

### Systemd Timer (Recommended)

See `systemd/` directory for example service and timer files.

```bash
sudo cp systemd/node-health.service /etc/systemd/system/
sudo cp systemd/node-health.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now node-health.timer
```

## Manual Intervention

### Locking Failover

To prevent automatic failovers during maintenance:

```bash
touch ~/.local/state/node-health/LOCK
```

To resume:

```bash
rm ~/.local/state/node-health/LOCK
```

### Resetting Cooldown

To force an immediate failover check:

```bash
rm ~/.local/state/node-health/your-service.last_switch
```

## Monitoring

### Log Output

The script logs to stdout with timestamps and severity levels:

```
[2026-01-09 15:30:00 UTC] [INFO] Checking service: example-service
[2026-01-09 15:30:01 UTC] [INFO] Primary healthy: True
[2026-01-09 15:30:02 UTC] [INFO] Mirror healthy: True
[2026-01-09 15:30:03 UTC] [INFO] example-service: DNS already correct (PRIMARY)
```

### Discord Notifications

Failover events trigger Discord alerts:

```
🚨 EXAMPLE-SERVICE failover
→ Switched to MIRROR
IPv4: 5.6.7.8 | IPv6: 2001:db8::2
Primary healthy: False
Mirror healthy: True
```

## Troubleshooting

### Script Won't Run

- Verify `.env` file exists and contains valid credentials
- Check Python version: `python3 --version` (3.8+ required)
- Install dependencies: `pip install -r requirements.txt`

### DNS Not Updating

- Verify Cloudflare API token has DNS edit permissions
- Check zone ID is correct: `CF_ZONE_ID` in `.env`
- Look for lock file: `~/.local/state/node-health/LOCK`
- Check cooldown hasn't been triggered (5 min default)

### Health Checks Failing

- Test endpoints manually: `curl https://your-endpoint/health`
- Increase `HTTP_TIMEOUT` if endpoints are slow
- Use `--verbose` flag to see detailed health check results

## Security Considerations

- Store `.env` file securely (never commit to git)
- Use restrictive Cloudflare API token with minimal permissions
- Consider running script as dedicated user with limited privileges
- Regularly rotate API credentials

## Contributing

All contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License

## Support

- Issues: https://github.com/patrickbeane/node-health/issues
- Documentation: https://github.com/patrickbeane/node-health/wiki

## Acknowledgments

Built for managing high-availability infrastructure with Cloudflare DNS.
