# MUTEX Daemon (mutexd) - Configuration File Documentation

## Overview

The MUTEX daemon (`mutexd`) is a userspace service that manages kernel-level proxy operations. It reads configuration from a JSON file, creates a proxy file descriptor via the `mprox_create()` syscall, and applies configuration to the kernel module through that file descriptor.

---

## Configuration File Location

Default configuration file locations (searched in order):
1. `/etc/mutex/mutex.conf`
2. Path specified with `-c` flag

---

## Configuration Format

The configuration file is in JSON format with the following top-level sections:

```json
{
  "version": "1.0",
  "daemon": { ... },
  "proxy": { ... },
  "routing": { ... },
  "dns": { ... },
  "process_filtering": { ... },
  "performance": { ... },
  "monitoring": { ... }
}
```

---

## Configuration Sections

### 1. Daemon Configuration

Controls daemon behavior and logging.

```json
"daemon": {
  "name": "mutexd",
  "pid_file": "/var/run/mutexd.pid",
  "log_file": "/var/log/mutexd.log",
  "log_level": "info"
}
```

**Fields:**
- `name` (string): Daemon name for logging
- `pid_file` (string): Path to PID file
- `log_file` (string): Path to log file
- `log_level` (string): Log verbosity level
  - Valid values: `"error"`, `"warn"`, `"info"`, `"debug"`

---

### 2. Proxy Configuration

Defines the proxy server settings.

```json
"proxy": {
  "enabled": true,
  "type": "socks5",
  "server": "127.0.0.1",
  "port": 1080,
  "authentication": {
    "enabled": false,
    "username": "",
    "password": ""
  },
  "fallback_servers": [
    {
      "server": "proxy.example.com",
      "port": 1080,
      "priority": 2
    }
  ]
}
```

**Fields:**
- `enabled` (boolean): Enable/disable proxying
- `type` (string): Proxy protocol type
  - Valid values: `"socks4"`, `"socks5"`, `"http"`, `"https"`
- `server` (string): Proxy server IP address or hostname
- `port` (integer): Proxy server port (1-65535)
- `authentication` (object): Authentication settings
  - `enabled` (boolean): Enable authentication
  - `username` (string): Username for proxy authentication
  - `password` (string): Password for proxy authentication
- `fallback_servers` (array): List of fallback proxy servers
  - `server` (string): Fallback server address
  - `port` (integer): Fallback server port
  - `priority` (integer): Priority (lower = higher priority)

---

### 3. Routing Configuration

Controls how traffic is routed through the proxy.

```json
"routing": {
  "mode": "transparent",
  "bypass_local": true,
  "bypass_cidrs": [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8"
  ],
  "force_proxy": [
    "*.google.com",
    "*.youtube.com"
  ]
}
```

**Fields:**
- `mode` (string): Routing mode
  - `"direct"`: No proxying (bypass mode)
  - `"transparent"`: Transparent proxying (default)
  - `"forced"`: Force all traffic through proxy
- `bypass_local` (boolean): Bypass proxy for local networks
- `bypass_cidrs` (array of strings): CIDR ranges to bypass proxy
- `force_proxy` (array of strings): Domain patterns to always proxy
  - Supports wildcards: `*.example.com`

---

### 4. DNS Configuration

Controls DNS resolution and caching.

```json
"dns": {
  "proxy_dns": true,
  "dns_server": "8.8.8.8",
  "dns_port": 53,
  "cache_enabled": true,
  "cache_ttl": 300
}
```

**Fields:**
- `proxy_dns` (boolean): Route DNS queries through proxy
- `dns_server` (string): DNS server address
- `dns_port` (integer): DNS server port
- `cache_enabled` (boolean): Enable DNS caching
- `cache_ttl` (integer): Cache TTL in seconds

---

### 5. Process Filtering Configuration

Filter which processes use the proxy.

```json
"process_filtering": {
  "enabled": false,
  "mode": "whitelist",
  "processes": [
    "firefox",
    "chrome",
    "curl"
  ]
}
```

**Fields:**
- `enabled` (boolean): Enable process filtering
- `mode` (string): Filter mode
  - `"none"`: No filtering (all processes)
  - `"whitelist"`: Only listed processes use proxy
  - `"blacklist"`: All except listed processes use proxy
- `processes` (array of strings): Process names to filter

---

### 6. Performance Configuration

Performance tuning parameters.

```json
"performance": {
  "max_connections": 10000,
  "connection_timeout": 300,
  "buffer_size": 8192
}
```

**Fields:**
- `max_connections` (integer): Maximum concurrent connections
- `connection_timeout` (integer): Connection timeout in seconds
- `buffer_size` (integer): Buffer size in bytes

---

### 7. Monitoring Configuration

Statistics and monitoring settings.

```json
"monitoring": {
  "enabled": true,
  "stats_interval": 60,
  "export_format": "json"
}
```

**Fields:**
- `enabled` (boolean): Enable monitoring
- `stats_interval` (integer): Statistics logging interval in seconds
- `export_format` (string): Statistics export format
  - Valid values: `"json"`, `"text"`

---

## Example Configurations

### Minimal Configuration

The simplest possible configuration:

```json
{
  "version": "1.0",
  "proxy": {
    "enabled": true,
    "type": "socks5",
    "server": "127.0.0.1",
    "port": 1080
  }
}
```

### SOCKS5 Proxy with Authentication

```json
{
  "version": "1.0",
  "proxy": {
    "enabled": true,
    "type": "socks5",
    "server": "proxy.example.com",
    "port": 1080,
    "authentication": {
      "enabled": true,
      "username": "myuser",
      "password": "mypassword"
    }
  },
  "routing": {
    "mode": "transparent",
    "bypass_local": true
  }
}
```

### HTTP Proxy for Corporate Network

```json
{
  "version": "1.0",
  "daemon": {
    "log_level": "debug"
  },
  "proxy": {
    "enabled": true,
    "type": "http",
    "server": "proxy.company.com",
    "port": 8080,
    "authentication": {
      "enabled": true,
      "username": "employee",
      "password": "pass123"
    }
  },
  "routing": {
    "mode": "transparent",
    "bypass_cidrs": [
      "10.0.0.0/8",
      "192.168.0.0/16"
    ],
    "force_proxy": [
      "*.external-site.com"
    ]
  },
  "dns": {
    "proxy_dns": true,
    "dns_server": "10.0.0.1"
  }
}
```

### Per-Process Filtering

Only proxy traffic from specific applications:

```json
{
  "version": "1.0",
  "proxy": {
    "enabled": true,
    "type": "socks5",
    "server": "127.0.0.1",
    "port": 1080
  },
  "process_filtering": {
    "enabled": true,
    "mode": "whitelist",
    "processes": [
      "firefox",
      "chrome",
      "wget",
      "curl"
    ]
  }
}
```

---

## Hot-Reload

The daemon watches the configuration file for changes using inotify. When the file is modified:

1. Daemon receives `IN_MODIFY` event
2. Configuration is re-parsed and validated
3. If valid, new configuration is applied to the proxy fd
4. Changes take effect immediately without restart

**To reload manually:**
```bash
# Send SIGHUP signal
sudo kill -HUP $(cat /var/run/mutexd.pid)

# Or use mutexctl
sudo mutexctl reload
```

---

## Validation

The daemon validates configuration on load and reload:

- Required fields must be present
- Port numbers must be in valid range (1-65535)
- IP addresses must be valid IPv4/IPv6
- Proxy type must be supported
- Performance values must be reasonable

**Test configuration without starting daemon:**
```bash
sudo mutexd -t -c /etc/mutex/mutex.conf
```

---

## Configuration Priority

When multiple instances run with different configurations:

1. Each daemon creates its own proxy fd via `mprox_create()`
2. Each fd has independent configuration
3. Process filtering determines which fd handles each process
4. Last matching configuration wins for a given process

---

## Security Considerations

### File Permissions

Recommended permissions for configuration file:
```bash
sudo chown root:root /etc/mutex/mutex.conf
sudo chmod 600 /etc/mutex/mutex.conf
```

### Sensitive Data

- Proxy passwords are stored in plaintext in the config file
- Use file permissions to protect sensitive data
- Consider using environment variables or secrets management
- Avoid committing passwords to version control

### Capabilities

The daemon requires `CAP_NET_ADMIN` capability to:
- Call `mprox_create()` syscall
- Apply configuration to kernel module

---

## Troubleshooting

### Configuration Errors

**Problem:** Daemon fails to start with "Configuration validation failed"

**Solution:**
1. Test configuration: `sudo mutexd -t -c /etc/mutex/mutex.conf`
2. Check syslog for specific validation errors
3. Verify JSON syntax with `jsonlint` or `jq`

### Proxy Not Working

**Problem:** Proxy is enabled but traffic not being proxied

**Solution:**
1. Check daemon status: `sudo mutexctl status`
2. Verify syscall is available: `dmesg | grep mprox`
3. Check proxy server is reachable
4. Review routing rules in configuration

### Hot-Reload Not Working

**Problem:** Configuration changes don't take effect

**Solution:**
1. Check daemon is running: `sudo mutexctl status`
2. Verify inotify is working: Check syslog for reload messages
3. Manually reload: `sudo mutexctl reload`
4. Restart daemon if needed: `sudo mutexctl restart`

---

## Environment-Specific Configs

### Development
```bash
sudo cp /etc/mutex/mutex.conf /etc/mutex/mutex-dev.conf
# Edit development settings
sudo mutexd -c /etc/mutex/mutex-dev.conf -f
```

### Production
```bash
# Use systemd service with production config
sudo systemctl start mutexd
```

### Testing
```bash
# Test without daemonizing
sudo mutexd -c /etc/mutex/mutex-test.conf -f -v
```

---

## See Also

- [Daemon Usage Guide](DAEMON_USAGE.md)
- [API Documentation](../../userspace/README.md)
- [MUTEX Project Documentation](../../../docs/)

---

*Last Updated: December 20, 2025*  
*Part of MUTEX (Multi-User Threaded Exchange Xfer)*
