# MUTEX Daemon - Usage Guide

## Overview

The MUTEX daemon (`mutexd`) provides kernel-level proxy services by managing configuration files and communicating with the kernel module through file descriptors created via the `mprox_create()` syscall.

---

## Installation

### From Source

```bash
cd /home/areeb/MUTEX/src/userspace/daemon
make
sudo make install
```

### With systemd

```bash
sudo make install-systemd
sudo systemctl daemon-reload
sudo systemctl enable mutexd
```

### With init script

```bash
sudo make install-init
sudo chkconfig mutexd on  # RHEL/CentOS
# or
sudo update-rc.d mutexd defaults  # Debian/Ubuntu
```

---

## Basic Usage

### Starting the Daemon

**Using mutexctl (recommended):**
```bash
sudo mutexctl start
```

**Using systemd:**
```bash
sudo systemctl start mutexd
```

**Manual start:**
```bash
sudo mutexd -c /etc/mutex/mutex.conf
```

**Foreground mode (for debugging):**
```bash
sudo mutexd -f -v
```

### Stopping the Daemon

```bash
sudo mutexctl stop
# or
sudo systemctl stop mutexd
```

### Checking Status

```bash
sudo mutexctl status
# or
sudo systemctl status mutexd
```

---

## Configuration

### Default Configuration

Located at: `/etc/mutex/mutex.conf`

### Editing Configuration

```bash
sudo nano /etc/mutex/mutex.conf
```

### Testing Configuration

Before starting the daemon, test your configuration:

```bash
sudo mutexd -t -c /etc/mutex/mutex.conf
```

### Reloading Configuration

After editing, reload without restart:

```bash
sudo mutexctl reload
# or
sudo systemctl reload mutexd
# or
sudo kill -HUP $(cat /var/run/mutexd.pid)
```

---

## mutexctl Command Reference

The `mutexctl` utility provides easy management of the daemon.

### Commands

#### start
Start the daemon if not already running.

```bash
sudo mutexctl start
```

#### stop
Stop the running daemon gracefully.

```bash
sudo mutexctl stop
```

#### restart
Stop and start the daemon.

```bash
sudo mutexctl restart
```

#### reload
Reload configuration without restarting.

```bash
sudo mutexctl reload
```

#### status
Show current daemon status.

```bash
sudo mutexctl status
```

Output:
```
Daemon is running (PID 1234)
Command: (mutexd)
State: S
CPU time: user=100 system=50
```

#### stats
Display proxy statistics.

```bash
sudo mutexctl stats
```

Output:
```
Proxy Statistics:
  Packets proxied:     12345
  Packets direct:      6789
  Bytes sent:          1234567890
  Bytes received:      9876543210
  Connections active:  42
  Connections total:   1000
  Errors:              5
```

### Options

**-p, --pid-file FILE**  
Specify custom PID file location.

```bash
sudo mutexctl -p /var/run/mutexd-custom.pid status
```

---

## mutexd Command Reference

The main daemon executable.

### Synopsis

```bash
mutexd [OPTIONS]
```

### Options

**-c, --config FILE**  
Specify configuration file path.

```bash
sudo mutexd -c /etc/mutex/custom.conf
```

**-f, --foreground**  
Run in foreground (don't daemonize).

```bash
sudo mutexd -f
```

**-t, --test**  
Test configuration and exit.

```bash
sudo mutexd -t -c /etc/mutex/mutex.conf
```

**-v, --verbose**  
Enable verbose output (debug mode).

```bash
sudo mutexd -f -v
```

**-V, --version**  
Print version and exit.

```bash
mutexd -V
```

**-h, --help**  
Print help message.

```bash
mutexd -h
```

---

## Running Multiple Instances

You can run multiple daemon instances with different configurations:

### Instance 1: SOCKS5 Proxy

```bash
# Create config
sudo cp /etc/mutex/mutex.conf /etc/mutex/mutex-socks5.conf
sudo nano /etc/mutex/mutex-socks5.conf
# Set: "pid_file": "/var/run/mutexd-socks5.pid"

# Start instance
sudo mutexd -c /etc/mutex/mutex-socks5.conf
```

### Instance 2: HTTP Proxy

```bash
# Create config
sudo cp /etc/mutex/mutex.conf /etc/mutex/mutex-http.conf
sudo nano /etc/mutex/mutex-http.conf
# Set: "pid_file": "/var/run/mutexd-http.pid"

# Start instance
sudo mutexd -c /etc/mutex/mutex-http.conf
```

### Managing Multiple Instances

```bash
# Status
sudo mutexctl -p /var/run/mutexd-socks5.pid status
sudo mutexctl -p /var/run/mutexd-http.pid status

# Stop specific instance
sudo mutexctl -p /var/run/mutexd-socks5.pid stop
```

---

## Signals

The daemon responds to the following signals:

| Signal  | Action                        |
|---------|-------------------------------|
| SIGHUP  | Reload configuration          |
| SIGTERM | Graceful shutdown             |
| SIGINT  | Graceful shutdown (Ctrl+C)    |
| SIGKILL | Force kill (not recommended)  |

### Examples

```bash
# Reload configuration
sudo kill -HUP $(cat /var/run/mutexd.pid)

# Graceful shutdown
sudo kill -TERM $(cat /var/run/mutexd.pid)
```

---

## Logging

### Log Locations

- **Daemon log:** `/var/log/mutexd.log`
- **System log:** Check syslog/journald

### Viewing Logs

**Daemon log file:**
```bash
sudo tail -f /var/log/mutexd.log
```

**System log (systemd):**
```bash
sudo journalctl -u mutexd -f
```

**System log (syslog):**
```bash
sudo tail -f /var/log/syslog | grep mutexd
```

### Log Levels

Control log verbosity in configuration:

```json
"daemon": {
  "log_level": "debug"
}
```

Levels (least to most verbose):
- `error`: Only errors
- `warn`: Warnings and errors
- `info`: Informational messages (default)
- `debug`: Detailed debugging information

---

## Systemd Integration

### Service Management

```bash
# Enable auto-start on boot
sudo systemctl enable mutexd

# Disable auto-start
sudo systemctl disable mutexd

# Start service
sudo systemctl start mutexd

# Stop service
sudo systemctl stop mutexd

# Restart service
sudo systemctl restart mutexd

# Reload configuration
sudo systemctl reload mutexd

# Check status
sudo systemctl status mutexd
```

### View Logs

```bash
# Follow logs
sudo journalctl -u mutexd -f

# Last 100 lines
sudo journalctl -u mutexd -n 100

# Since boot
sudo journalctl -u mutexd -b

# Filter by time
sudo journalctl -u mutexd --since "1 hour ago"
```

---

## Troubleshooting

### Daemon Won't Start

**Check if syscall is available:**
```bash
dmesg | grep mprox_create
```

If not found, the kernel may not have the syscall compiled in.

**Check permissions:**
```bash
sudo mutexd -f -v
```

The daemon requires root (or `CAP_NET_ADMIN`).

**Verify configuration:**
```bash
sudo mutexd -t
```

### Proxy Not Working

**Check daemon is running:**
```bash
sudo mutexctl status
```

**Check proxy configuration:**
```bash
cat /etc/mutex/mutex.conf | grep -A 10 '"proxy"'
```

**Test proxy server manually:**
```bash
curl -x socks5://127.0.0.1:1080 https://example.com
```

**Check kernel logs:**
```bash
dmesg | tail -50
```

### High CPU Usage

**Check connection count:**
```bash
sudo mutexctl stats
```

**Adjust performance settings:**
```json
"performance": {
  "max_connections": 5000,
  "connection_timeout": 60,
  "buffer_size": 4096
}
```

**Enable debug logging:**
```bash
sudo mutexd -f -v
```

### Configuration Not Reloading

**Check file watch is active:**
```bash
sudo lsof -p $(cat /var/run/mutexd.pid) | grep inotify
```

**Manually reload:**
```bash
sudo mutexctl reload
```

**Restart if needed:**
```bash
sudo mutexctl restart
```

---

## Best Practices

### Production Deployment

1. **Use systemd service:**
   ```bash
   sudo make install-systemd
   sudo systemctl enable mutexd
   ```

2. **Set appropriate log level:**
   ```json
   "daemon": {
     "log_level": "info"
   }
   ```

3. **Monitor statistics:**
   ```bash
   # Add to cron or monitoring system
   */5 * * * * /usr/local/bin/mutexctl stats >> /var/log/mutex-stats.log
   ```

4. **Secure configuration file:**
   ```bash
   sudo chmod 600 /etc/mutex/mutex.conf
   sudo chown root:root /etc/mutex/mutex.conf
   ```

### Development

1. **Run in foreground with debug:**
   ```bash
   sudo mutexd -f -v
   ```

2. **Use test configuration:**
   ```bash
   sudo mutexd -c /etc/mutex/mutex-test.conf -f
   ```

3. **Monitor logs in real-time:**
   ```bash
   sudo tail -f /var/log/mutexd.log
   ```

---

## Examples

### Basic SOCKS5 Proxy

```bash
# Create minimal config
sudo cat > /etc/mutex/mutex.conf << 'EOF'
{
  "version": "1.0",
  "proxy": {
    "enabled": true,
    "type": "socks5",
    "server": "127.0.0.1",
    "port": 1080
  }
}
EOF

# Start daemon
sudo mutexctl start

# Check status
sudo mutexctl status

# View statistics
sudo mutexctl stats
```

### Corporate HTTP Proxy

```bash
# Create corporate config
sudo cat > /etc/mutex/mutex-corp.conf << 'EOF'
{
  "version": "1.0",
  "daemon": {
    "name": "mutexd-corp",
    "pid_file": "/var/run/mutexd-corp.pid"
  },
  "proxy": {
    "enabled": true,
    "type": "http",
    "server": "proxy.company.com",
    "port": 8080,
    "authentication": {
      "enabled": true,
      "username": "employee",
      "password": "secret"
    }
  }
}
EOF

# Start with custom config
sudo mutexd -c /etc/mutex/mutex-corp.conf

# Manage with mutexctl
sudo mutexctl -p /var/run/mutexd-corp.pid status
```

---

## See Also

- [Configuration File Documentation](CONFIG.md)
- [MUTEX Project Documentation](../../../docs/)
- [API Documentation](../../userspace/README.md)

---

*Last Updated: December 20, 2025*  
*Part of MUTEX (Multi-User Threaded Exchange Xfer)*
