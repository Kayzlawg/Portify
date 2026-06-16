# Portify

**Minecraft Server Port Forwarder**

Portify is a lightweight Windows application that automates port forwarding and firewall configuration for Minecraft servers. It uses UPnP to automatically configure your router — no need to manually log into your admin panel.

![Portify Screenshot](resources/portify.ico)

## Features

- **One-click port forwarding** - Automatically forwards ports via UPnP
- **Firewall management** - Adds/removes Windows Defender Firewall rules (requires admin)
- **Java & Bedrock support**  Pre-configured ports for both editions
- **Custom ports** - Forward any port with TCP, UDP, or both
- **Connection testing** - Verify your server is reachable from the internet
- **CGNAT/Double NAT detection** - Warns you if port forwarding won't work
- **Manual setup guides** - Step-by-step instructions for TP-Link, Netgear, ASUS, and Linksys routers

## Requirements

- Windows 10/11
- Python 3.6+ (for running from source)
- Router with UPnP enabled (default on most home routers)
- Administrator privileges (for firewall rule management)

## Installation

### Option 1: Standalone Executable

Download the latest `Portify.exe` from the [Releases](https://github.com/) page. No installation required — just double-click to run.

### Option 2: From Source

```bash
git clone https://github.com/YOUR_USERNAME/Portify.git
cd Portify
pip install customtkinter requests Pillow
python portify.pyw
```

## Usage

1. Make sure your Minecraft server is running
2. Launch `Portify.exe`
3. Accept the UAC prompt (required for firewall rules)
4. Select your Minecraft version:
   - **Java** — port 25565 TCP
   - **Bedrock** — port 19132 UDP
   - **Custom** — enter any port and protocol
5. Click **"Open Connection Port"**
6. Use the **Test** button to verify connectivity
7. Share your `IP:port` with friends

> **Note:** Keep Portify running while your server is active. Closing it will remove the UPnP port mapping.

## Building from Source

To create a standalone `.exe`:

```bash
pip install pyinstaller
python -m PyInstaller --clean portify.spec
```

The output will be in `dist/Portify.exe`.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No UPnP device found" | Enable UPnP in your router settings |
| CGNAT warning | Your ISP shares IPs - use a tunnel service like [Playit.gg](https://playit.gg) or [ngrok](https://ngrok.com) |
| Double NAT detected | Set your ISP modem to Bridge Mode |
| Test failed | Ensure your Minecraft server is fully loaded before testing |
| Firewall blocked | Run as Administrator (right-click -> Run as administrator)

## License

MIT

Also this was mostly vibe-coded dont hate me since it works
