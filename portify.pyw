import sys
import os
import socket
import requests
import threading
import ipaddress
import time
import atexit
import subprocess
import tempfile
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Debug logging (visible since .pyw has no console) ─────────────────────────
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "portify.log")

def log(msg):
    """Append a timestamped message to the log file."""
    try:
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import re
from urllib.parse import urlparse

# ── Theme ─────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# VAULT palette
BG          = "#111111"
CARD        = "#1a1a1a"
CARD_HOVER  = "#222222"
BORDER      = "#2a2a2a"
INPUT_BG    = "#0d0d0d"
OVERLAY     = "#161616"

# GOLD accent
GOLD        = "#C8A96E"
GOLD_HOV    = "#b08f56"
GOLD_DIM    = "#8a6e3a"
GOLD_BG     = "#2a2418"

TEXT_MAIN   = "#e8e0d4"
TEXT_MUTED  = "#6b6560"
TEXT_DIM    = "#3d3935"

SUCCESS     = "#4caf50"
DANGER      = "#e53935"
WARNING     = "#fbc02d"

FONT        = "Segoe UI"
FONT_MONO   = "Cascadia Code"

# ── Admin helpers ──────────────────────────────────────────────────────────────

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def add_firewall_rule(port, protocol):
    """Add firewall rule — only works when already running as admin.
    Non-admin runs skip silently (no UAC prompts)."""
    if os.name != "nt" or not is_admin():
        return
    try:
        pu = protocol.upper()
        subprocess.run(
            f'netsh advfirewall firewall delete rule '
            f'name="Portify - Minecraft {port} {pu}"',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule '
            f'name="Portify - Minecraft {port} {pu}" '
            f'dir=in action=allow protocol={pu} localport={port} profile=any',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
    except Exception as e:
        print(f"FW add error: {e}")


def remove_firewall_rule(port, protocol):
    """Remove firewall rule — only works when already running as admin."""
    if os.name != "nt" or not is_admin():
        return
    try:
        subprocess.run(
            f'netsh advfirewall firewall delete rule '
            f'name="Portify - Minecraft {port} {protocol.upper()}"',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
    except Exception as e:
        print(f"FW remove error: {e}")


# ── UPnP Manager (manual SSDP + SOAP — no upnpy dependency issues) ──────────

class UPnPManager:
    def __init__(self):
        self.discovered = False
        self.active_forwards = {}
        self.router_external_ip = None
        self.discovery_error = None
        self._igd_base_url = None       # e.g. "http://192.168.1.1:49152"
        self._control_url = None         # e.g. "/upnp/control/WANIPConnection0"
        self._service_type = None        # e.g. "urn:schemas-upnp-org:service:WANIPConnection:1"
        self._router_name = None

    # ── SSDP discovery ───────────────────────────────────────────────────

    def _get_default_gateway(self):
        """Get the default gateway IP. Tries multiple methods for cross-platform reliability."""
        # Method 1: Parse from system routing table
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["powershell", "-Command",
                     "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                     "Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)"],
                    capture_output=True, text=True, timeout=5,
                    creationflags=0x08000000
                )
                gw = result.stdout.strip()
                if gw and gw.count(".") == 3:
                    return gw
        except Exception:
            pass

        # Method 2: Derive from local IP (works for most /24 home networks)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            parts[-1] = "1"
            return ".".join(parts)
        except Exception:
            return None

    def _probe_gateway_upnp(self, gateway_ip):
        """Try to find UPnP IGD on the gateway by scanning common ports and paths.
        Uses concurrent threads for fast probing — all requests run in parallel."""
        common_ports = [
            49152, 49153, 49154, 49155,
            80, 8080, 8443,
            5000, 5431,
            2869, 1900,
            49500, 55555,
        ]
        common_paths = [
            "/IGDdevicedesc_brlan0.xml", "/IGDdevicedesc_brlan1.xml",
            "/IGDdevicedesc.xml", "/igd.xml",
            "/rootDesc.xml", "/DeviceDescription.xml",
            "/description.xml", "/devicedesc.xml",
            "/upnp/devicedesc.xml", "/upnp/IGD.xml",
            "/gatedesc.xml", "/InternetGatewayDevice.xml",
            "/WANDevice.xml", "/wan.xml",
            "/api/device/description", "/DeviceDescription1.xml",
        ]

        # Build all URL candidates
        urls = [(port, path, f"http://{gateway_ip}:{port}{path}")
                for port in common_ports for path in common_paths]

        found = threading.Event()
        result = [None]

        def probe_one(url):
            if found.is_set():
                return
            try:
                r = requests.get(url, timeout=1, verify=False)
                if r.status_code == 200 and len(r.text) > 100:
                    text = r.text[:500].lower()
                    if ("internetgatewaydevice" in text
                            or "wanipconnection" in text
                            or "wanpppconnection" in text):
                        if not found.is_set():
                            result[0] = url
                            found.set()
            except Exception:
                pass

        # Run all probes concurrently, max 20 at a time
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(probe_one, url) for _, _, url in urls]
            # Wait up to 4 seconds total for any result
            found.wait(timeout=4)
            # Cancel remaining if we found one
            if found.is_set():
                for f in futures:
                    f.cancel()

        return result[0]

    def _ssdp_discover(self, timeout=5):
        """Send M-SEARCH and collect responses. Uses a single ssdp:all search
        (covers every UPnP device) with a short MX wait, then falls back to
        targeted searches only if the broad search returns nothing."""
        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900

        def _search(st, wait):
            """Send one M-SEARCH and collect responses for *wait* seconds."""
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(0.5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            # Bind to all interfaces so multicast replies arrive reliably
            sock.bind(("", 0))

            msg = "\r\n".join([
                "M-SEARCH * HTTP/1.1",
                f"HOST: {SSDP_ADDR}:{SSDP_PORT}",
                'MAN: "ssdp:discover"',
                f"MX: {wait}",
                f"ST: {st}",
                "", "",
            ])
            try:
                sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
            except Exception:
                sock.close()
                return []

            results = []
            seen = set()
            deadline = time.time() + wait
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode("utf-8", errors="ignore")
                    loc_match = re.search(r"[Ll]ocation:\s*(.+?)\r?\n", response)
                    if loc_match:
                        loc = loc_match.group(1).strip()
                        if loc not in seen:
                            seen.add(loc)
                            results.append((addr[0], loc))
                except socket.timeout:
                    continue
                except Exception:
                    break
            sock.close()
            return results

        # 1. Broad search first — ssdp:all finds everything
        results = _search("ssdp:all", min(timeout, 3))
        if results:
            return results

        # 2. Targeted fallback — IGD-specific search
        results = _search(
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            max(2, timeout - 3),
        )
        return results

    @staticmethod
    def _fetch_device_xml(url):
        """Fetch device description XML, return text or None."""
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        return None

    def _find_igd_service(self, xml_text, base_url):
        """Parse device XML to find WANIPConnection / WANPPPConnection service control URL.
        Handles nested device hierarchies by searching all device entries."""
        # Quick check: does this XML contain any WAN connection service?
        has_wan = bool(re.search(r"WANIPConnection|WANPPPConnection", xml_text))
        if not has_wan:
            return None, None

        # Find all <service> blocks (handles nested XML hierarchies)
        # Use case-insensitive matching for broader compatibility
        svc_blocks = re.findall(r"<service\b[^>]*>(.*?)</service>", xml_text, re.DOTALL | re.IGNORECASE)

        for svc_pattern in [r"WANIPConnection", r"WANPPPConnection"]:
            for block in svc_blocks:
                if re.search(svc_pattern, block, re.IGNORECASE):
                    type_match = re.search(r"<serviceType\b[^>]*>(.*?)</serviceType>", block, re.DOTALL | re.IGNORECASE)
                    ctrl_match = re.search(r"<controlURL\b[^>]*>(.*?)</controlURL>", block, re.DOTALL | re.IGNORECASE)
                    if type_match and ctrl_match:
                        service_type = type_match.group(1).strip()
                        control_path = ctrl_match.group(1).strip()
                        if control_path.startswith("http"):
                            return control_path, service_type
                        control_url = base_url.rstrip("/") + "/" + control_path.lstrip("/")
                        return control_url, service_type
        return None, None

    def discover(self):
        """Find IGD via SSDP, then test the SOAP endpoint.
        Falls back to probing the default gateway if SSDP fails.
        Retries up to 3 times like the original upnpy-based version."""
        self.discovery_error = None
        try:
            for attempt in range(3):
                # 1. SSDP search
                devices = self._ssdp_discover(timeout=4)

                # 2. If SSDP failed, try probing the default gateway directly
                if not devices:
                    gateway = self._get_default_gateway()
                    if gateway:
                        igd_url = self._probe_gateway_upnp(gateway)
                        if igd_url:
                            from urllib.parse import urlparse
                            parsed = urlparse(igd_url)
                            devices = [(parsed.hostname, igd_url)]
                    else:
                        self.discovery_error = "No UPnP devices found and could not determine default gateway."
                        return False

                if devices:
                    # 3. Try each device, looking for IGD services
                    for addr, location in devices:
                        xml_text = self._fetch_device_xml(location)
                        if not xml_text:
                            continue

                        from urllib.parse import urlparse
                        parsed = urlparse(location)
                        base_url = f"{parsed.scheme}://{parsed.netloc}"

                        control_url, service_type = self._find_igd_service(xml_text, base_url)
                        if not control_url:
                            continue

                        # Test the SOAP endpoint with GetExternalIPAddress
                        resp = self._soap_call(control_url, service_type, "GetExternalIPAddress", {})
                        ip = None
                        if resp:
                            ip = resp.get("NewExternalIPAddress")
                        if ip is None:
                            alt_type = service_type.replace("WANIP", "WANPPP")
                            resp2 = self._soap_call(control_url, alt_type, "GetExternalIPAddress", {})
                            if resp2:
                                ip = resp2.get("NewExternalIPAddress")

                        # We found a working IGD
                        self._igd_base_url = base_url
                        self._control_url = control_url
                        self._service_type = service_type
                        self.router_external_ip = ip

                        name_match = re.search(r"<friendlyName>(.*?)</friendlyName>", xml_text)
                        self._router_name = name_match.group(1).strip() if name_match else addr

                        self.discovered = True
                        return True

                # No devices found this attempt — wait before retry
                if attempt < 2:
                    time.sleep(2)

            self.discovery_error = "No UPnP gateway found. Enable UPnP on your router."
            return False

        except Exception as e:
            self.discovery_error = f"UPnP discovery error: {e}"
            return False

    # ── SOAP helpers ─────────────────────────────────────────────────────

    def _soap_call(self, control_url, service_type, action, args):
        """Send a SOAP UPnP action. Returns parsed response dict or None."""
        arg_xml = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())

        bodies = [
            (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
                ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:{action} xmlns:u="{service_type}">{arg_xml}</u:{action}></s:Body>'
                '</s:Envelope>'
            ),
            (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"'
                ' SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<SOAP-ENV:Body><m:{action} xmlns:m="{service_type}">{arg_xml}</m:{action}></SOAP-ENV:Body>'
                '</SOAP-ENV:Envelope>'
            ),
        ]

        headers = {
            "SOAPAction": f'"{service_type}#{action}"',
            "Content-Type": "text/xml",
        }

        for i, body in enumerate(bodies):
            try:
                r = requests.post(control_url, data=body, headers=headers, timeout=5)
                log(f"SOAP {action}: status={r.status_code}, len={len(r.text)}")
                if r.status_code == 200:
                    result = {}
                    for match in re.finditer(
                        r"<(?:[\w]+:)?(\w+)[^>]*>([^<]*)</(?:[\w]+:)?\w+>", r.text
                    ):
                        result[match.group(1)] = match.group(2)
                    return result if result else {}
            except Exception as e:
                log(f"SOAP {action} body#{i}: exception={e}")
                continue
        log(f"SOAP {action} failed: all body formats exhausted")
        return None

    def _get_external_ip(self):
        """Call GetExternalIPAddress — returns IP string or None."""
        resp = self._soap_call(
            self._control_url, self._service_type,
            "GetExternalIPAddress", {}
        )
        return resp.get("NewExternalIPAddress") if resp else None

    # ── Port mapping ─────────────────────────────────────────────────────

    def add_mapping(self, external_port, protocol, local_ip,
                    description="Minecraft Server via Portify"):
        if not self.discovered or not self._control_url:
            return False, "UPnP is not initialized."
        protocol = protocol.upper()
        args = {
            "NewRemoteHost": "",
            "NewExternalPort": str(int(external_port)),
            "NewProtocol": protocol,
            "NewInternalPort": str(int(external_port)),
            "NewInternalClient": local_ip,
            "NewEnabled": "1",
            "NewPortMappingDescription": description,
            "NewLeaseDuration": "0",
        }
        resp = self._soap_call(
            self._control_url, self._service_type,
            "AddPortMapping", args
        )
        if resp is None:
            return False, "Failed to add port mapping. Router may have rejected the request."
        self.active_forwards[(int(external_port), protocol)] = description
        add_firewall_rule(external_port, protocol)
        return True, None

    def delete_mapping(self, external_port, protocol):
        if not self.discovered or not self._control_url:
            return False, "UPnP is not initialized."
        protocol = protocol.upper()
        args = {
            "NewRemoteHost": "",
            "NewExternalPort": str(int(external_port)),
            "NewProtocol": protocol,
        }
        resp = self._soap_call(
            self._control_url, self._service_type,
            "DeletePortMapping", args
        )
        key = (int(external_port), protocol)
        if key in self.active_forwards:
            del self.active_forwards[key]
        remove_firewall_rule(external_port, protocol)
        if resp is None:
            return False, "Failed to delete port mapping."
        return True, None

    def clear_all(self):
        failed = []
        for port, proto in list(self.active_forwards.keys()):
            success, err = self.delete_mapping(port, proto)
            if not success:
                failed.append(f"{port}/{proto}")
        return failed


# ── Toast (compact) ───────────────────────────────────────────────────────────

class ToastManager:
    """Small compact toast that slides in from the top."""

    def __init__(self, root):
        self.root = root
        self._timer = None
        self._frame = None

    def show(self, message, style="info", duration=2800):
        if self._timer:
            self.root.after_cancel(self._timer)
        if self._frame and self._frame.winfo_exists():
            self._frame.destroy()

        colors = {
            "success": (SUCCESS, "#152215"),
            "error":   (DANGER,  "#221515"),
            "warning": (WARNING, "#222015"),
            "info":    (GOLD,    "#1e1c14"),
        }
        accent, bg = colors.get(style, colors["info"])

        font_size = 11 if style == "success" else 10
        frame_h = 32

        # Full-width toast: root width minus 8px margin each side
        toast_w = self.root.winfo_width() - 16
        self._frame = ctk.CTkFrame(self.root, fg_color=bg, corner_radius=6,
                                    border_color=accent, border_width=1,
                                    width=toast_w, height=frame_h)
        self._frame.pack_propagate(False)
        self._frame.place(x=8, y=-40)

        # thin left accent bar
        bar = ctk.CTkFrame(self._frame, width=3, fg_color=accent, corner_radius=0)
        bar.place(x=0, rely=0.15, relheight=0.70)

        lbl = ctk.CTkLabel(self._frame, text=message, text_color=TEXT_MAIN,
                           font=(FONT, font_size), anchor="w")
        lbl.pack(side="left", fill="both", expand=True, padx=(10, 4), pady=4)

        close = ctk.CTkButton(self._frame, text="✕", width=20, height=20,
                              fg_color="transparent", text_color=TEXT_MUTED,
                              hover_color="#333333", corner_radius=4,
                              font=(FONT, 8), command=self.hide)
        close.pack(side="right", padx=(0, 4), pady=4)

        self._frame.lift()
        self._slide(-40, 10, 5, 10, lambda: self._schedule_hide(duration))

    def _slide(self, start, target, step, delay, done=None):
        cur = [start]

        def tick():
            if not self._frame or not self._frame.winfo_exists():
                return
            if cur[0] < target:
                cur[0] = min(cur[0] + step, target)
                try:
                    self._frame.place(relx=0.5, y=cur[0], anchor="n")
                    self._frame.lift()
                except Exception:
                    pass
                if cur[0] < target:
                    self.root.after(delay, tick)
                elif done:
                    done()
            elif cur[0] > target:
                cur[0] = max(cur[0] - step, target)
                try:
                    self._frame.place(relx=0.5, y=cur[0], anchor="n")
                    self._frame.lift()
                except Exception:
                    pass
                if cur[0] > target:
                    self.root.after(delay, tick)
                elif done:
                    done()

        tick()

    def _schedule_hide(self, duration):
        self._timer = self.root.after(duration, self.hide)

    def hide(self):
        if self._timer:
            self.root.after_cancel(self._timer)
            self._timer = None
        if self._frame and self._frame.winfo_exists():
            self._slide(8, -40, 5, 8, self._frame.destroy)


# ── Main App ──────────────────────────────────────────────────────────────────

class PortifyApp(ctk.CTk):
    # segment indices for sliding bar
    SEG_LABELS = [("Java", "java"), ("Bedrock", "bedrock"), ("Custom", "custom")]

    def __init__(self):
        super().__init__()

        self.title("Portify")
        self.geometry("540x720")
        self.minsize(480, 560)
        self.configure(fg_color=BG)
        self._set_window_icon()

        self.upnp_mgr = UPnPManager()
        self.local_ip = "127.0.0.1"
        self.public_ip = "Detecting…"
        self.game_version = ctk.StringVar(value="java")
        self.custom_port = ctk.StringVar(value="25565")
        self.protocol_choice = ctk.StringVar(value="TCP")
        self._dot_animating = False
        self._pub_ip_visible = False
        self._loading_timer = None

        self.toast = ToastManager(self)
        self._build_ui()
        self._start_detection()

        self.protocol("WM_DELETE_WINDOW", self._on_exit)
        atexit.register(self._cleanup_atexit)

    # ── Build UI ───────────────────────────────────────────────────────────

    def _build_ui(self):
        self.scroll = ctk.CTkScrollableFrame(self, fg_color=BG, scrollbar_fg_color=BG,
                                              scrollbar_button_color=BORDER,
                                              scrollbar_button_hover_color=TEXT_DIM)
        self.scroll.pack(fill="both", expand=True)

        _p = 20  # horizontal padding

        # ── Header ──────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self.scroll, fg_color="transparent")
        header.pack(fill="x", padx=_p, pady=(16, 2))
        ctk.CTkLabel(header, text="Portify", text_color=TEXT_MAIN,
                     font=(FONT, 20, "bold"), anchor="w").pack(side="left")

        # version label
        ctk.CTkLabel(header, text="v1.0", text_color=TEXT_DIM,
                     font=(FONT, 9)).pack(side="right", padx=(0, 2))

        self._divider(self.scroll)

        # ── Admin warning ──────────────────────────────────────────────────
        self.admin_warn_frame = ctk.CTkFrame(self.scroll, fg_color="#1e1c14",
                                              corner_radius=8, border_color=WARNING,
                                              border_width=1)
        if not is_admin():
            self.admin_warn_frame.pack(fill="x", padx=_p, pady=(10, 0))
            ctk.CTkLabel(self.admin_warn_frame,
                         text="⚠  Running without administrator privileges",
                         text_color=WARNING, font=(FONT, 10, "bold"),
                         anchor="w").pack(anchor="w", padx=12, pady=(8, 2))
            ctk.CTkLabel(self.admin_warn_frame,
                         text="Right-click → Run as administrator for firewall rules.",
                         text_color=TEXT_MUTED, font=(FONT, 9),
                         anchor="w", justify="left").pack(anchor="w", padx=12, pady=(0, 8))

        # ── Status card ─────────────────────────────────────────────────────
        scard = ctk.CTkFrame(self.scroll, fg_color=CARD, corner_radius=10,
                              border_color=BORDER, border_width=1)
        scard.pack(fill="x", padx=_p, pady=(12, 0))

        # dot + label row
        sr = ctk.CTkFrame(scard, fg_color="transparent")
        sr.pack(fill="x", padx=14, pady=(12, 2))

        self.status_dot = ctk.CTkLabel(sr, text="●", text_color=WARNING,
                                       font=(FONT, 12))
        self.status_dot.pack(side="left", padx=(0, 6))

        self.status_label = ctk.CTkLabel(sr, text="Checking router…",
                                         text_color=TEXT_MUTED, font=(FONT, 11), anchor="w")
        self.status_label.pack(side="left")

        self.btn_refresh = ctk.CTkButton(sr, text="↻", width=28, height=28,
                                         fg_color="transparent", hover_color=CARD_HOVER,
                                         text_color=TEXT_MUTED, font=(FONT, 14),
                                         corner_radius=6, command=self._refresh)
        self.btn_refresh.pack(side="right")

        # IPs
        ips = ctk.CTkFrame(scard, fg_color="transparent")
        ips.pack(fill="x", padx=14, pady=(2, 12))

        left = ctk.CTkFrame(ips, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(left, text="INTERNAL", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(anchor="w")
        self.lbl_local_ip = ctk.CTkLabel(left, text="Detecting…",
                                         text_color=TEXT_MAIN, font=(FONT_MONO, 11), anchor="w")
        self.lbl_local_ip.pack(anchor="w")

        right = ctk.CTkFrame(ips, fg_color="transparent")
        right.pack(side="right", fill="x", expand=True)
        ctk.CTkLabel(right, text="EXTERNAL", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(anchor="w")

        # hidden external IP with reveal toggle
        ip_row = ctk.CTkFrame(right, fg_color="transparent")
        ip_row.pack(fill="x")
        self.lbl_pub_ip_hidden = ctk.CTkLabel(ip_row, text="● ● ● ● ● ● ● ● ● ●",
                                               text_color=TEXT_DIM, font=(FONT_MONO, 11), anchor="w")
        self.lbl_pub_ip_hidden.pack(side="left")
        self.lbl_pub_ip = ctk.CTkLabel(ip_row, text="", text_color=TEXT_MAIN,
                                       font=(FONT_MONO, 11), anchor="w")
        # don't pack yet — hidden by default

        self.btn_view_addr = ctk.CTkButton(ip_row, text="View Address", width=80, height=22,
                                           fg_color="transparent", hover_color=CARD_HOVER,
                                           text_color=GOLD, corner_radius=4,
                                           font=(FONT, 9), command=self._toggle_pub_ip)
        self.btn_view_addr.pack(side="right")

        # ── CGNAT warning (hidden) ──────────────────────────────────────────
        self.cgnat_frame = ctk.CTkFrame(self.scroll, fg_color="#1e1c14", corner_radius=8,
                                         border_color=WARNING, border_width=1)
        ctk.CTkLabel(self.cgnat_frame, text="⚠ Connection Restriction",
                     text_color=WARNING, font=(FONT, 10, "bold"),
                     anchor="w").pack(anchor="w", padx=12, pady=(8, 2))
        self.cgnat_desc = ctk.CTkLabel(self.cgnat_frame, text="", text_color=TEXT_MUTED,
                                       font=(FONT, 9), anchor="w", justify="left", wraplength=420)
        self.cgnat_desc.pack(anchor="w", padx=12, pady=(0, 8))

        # ── Config card ─────────────────────────────────────────────────────
        self._divider(self.scroll)
        config = ctk.CTkFrame(self.scroll, fg_color=CARD, corner_radius=10,
                               border_color=BORDER, border_width=1)
        config.pack(fill="x", padx=_p, pady=(12, 0))

        ctk.CTkLabel(config, text="PORT FORWARDING", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(anchor="w", padx=14, pady=(12, 8))

        # ── Segmented control ───────────────────────────────────────────────
        seg_outer = ctk.CTkFrame(config, fg_color=INPUT_BG, corner_radius=8)
        seg_outer.pack(fill="x", padx=14, pady=(0, 10))

        self._seg_btn_refs = {}
        for label, value in self.SEG_LABELS:
            btn = ctk.CTkButton(seg_outer, text=label, height=32,
                                font=(FONT, 11, "bold"), corner_radius=6,
                                fg_color="transparent", text_color=TEXT_MUTED,
                                hover_color="#333333",
                                command=lambda v=value: self._on_segment(v))
            btn.pack(side="left", fill="x", expand=True, padx=2, pady=2)
            self._seg_btn_refs[value] = btn

        # Set initial active state
        self._seg_btn_refs["java"].configure(fg_color=GOLD, text_color=BG)

        # port + protocol
        form = ctk.CTkFrame(config, fg_color="transparent")
        form.pack(fill="x", padx=14, pady=(0, 14))

        pc = ctk.CTkFrame(form, fg_color="transparent")
        pc.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(pc, text="Port", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 3))
        self.port_entry = ctk.CTkEntry(pc, textvariable=self.custom_port,
                                       height=34, font=(FONT_MONO, 12),
                                       fg_color=INPUT_BG, border_color=BORDER,
                                       text_color=TEXT_MAIN, corner_radius=6,
                                       placeholder_text_color=TEXT_DIM)
        self.port_entry.pack(fill="x")

        pr = ctk.CTkFrame(form, fg_color="transparent")
        pr.pack(side="right", padx=(10, 0))
        ctk.CTkLabel(pr, text="Protocol", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(anchor="w", pady=(0, 3))
        self.proto_menu = ctk.CTkOptionMenu(pr, variable=self.protocol_choice,
                                            values=["TCP", "UDP", "Both (Recommended)"],
                                            height=34, width=150,
                                            fg_color=INPUT_BG, button_color=BORDER,
                                            button_hover_color=TEXT_DIM,
                                            dropdown_fg_color=CARD,
                                            dropdown_hover_color=CARD_HOVER,
                                            dropdown_text_color=TEXT_MAIN,
                                            text_color=TEXT_MAIN, corner_radius=6,
                                            font=(FONT, 10))
        self.proto_menu.pack()
        self._pulse_on_click(self.proto_menu)

        # CTA
        self.btn_forward = ctk.CTkButton(
            config, text="Open Connection Port", height=40,
            font=(FONT, 12, "bold"), fg_color=GOLD, hover_color=GOLD_HOV,
            text_color=BG, corner_radius=8, command=self._on_forward
        )
        self.btn_forward.pack(fill="x", padx=14, pady=(0, 4))
        self._keep_btn_black(self.btn_forward)

        # Status label below the button
        self.forward_status = ctk.CTkLabel(config, text="", text_color=TEXT_DIM,
                                            font=(FONT, 9), anchor="center")
        self.forward_status.pack(fill="x", padx=14, pady=(0, 12))

        # ── Active Ports card ───────────────────────────────────────────────
        self._divider(self.scroll)
        acard = ctk.CTkFrame(self.scroll, fg_color=CARD, corner_radius=10,
                              border_color=BORDER, border_width=1)
        acard.pack(fill="x", padx=_p, pady=(12, 0))

        ctk.CTkLabel(acard, text="ACTIVE PORTS", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(anchor="w", padx=14, pady=(12, 4))

        self.active_container = ctk.CTkFrame(acard, fg_color="transparent")
        self.active_container.pack(fill="x", padx=14, pady=(0, 12))

        self.no_ports_label = ctk.CTkLabel(
            self.active_container,
            text="No active forwards yet.\nOpen a port above to get started.",
            text_color=TEXT_DIM, font=(FONT, 10), pady=16
        )
        self.no_ports_label.pack(fill="x")

        self.active_warn = ctk.CTkLabel(
            acard,
            text="⚠ Server must be running for connection tests to pass.",
            text_color=TEXT_DIM, font=(FONT, 8), anchor="w"
        )

        # ── Manual Guide card ──────────────────────────────────────────────
        self._divider(self.scroll)
        manual = ctk.CTkFrame(self.scroll, fg_color=CARD, corner_radius=10,
                               border_color=BORDER, border_width=1)
        manual.pack(fill="x", padx=_p, pady=(12, 0))

        mh = ctk.CTkFrame(manual, fg_color="transparent")
        mh.pack(fill="x", padx=14, pady=(12, 4))
        ctk.CTkLabel(mh, text="MANUAL SETUP", text_color=TEXT_DIM,
                     font=(FONT, 8, "bold")).pack(side="left")

        self.router_menu = ctk.CTkOptionMenu(
            mh, variable=ctk.StringVar(value="Select Router…"),
            values=["TP-Link", "Netgear", "ASUS", "Linksys"],
            width=130, height=28, fg_color=INPUT_BG, button_color=BORDER,
            button_hover_color=TEXT_DIM, dropdown_fg_color=CARD,
            dropdown_hover_color=CARD_HOVER, dropdown_text_color=TEXT_MAIN,
            text_color=TEXT_MUTED, corner_radius=6, font=(FONT, 10),
            command=self._show_manual_guide
        )
        self.router_menu.pack(side="right")
        self._pulse_on_click(self.router_menu)

        self.guide_label = ctk.CTkLabel(
            manual,
            text="Select your router brand for step-by-step\nmanual port forwarding instructions.",
            text_color=TEXT_DIM, font=(FONT, 9), anchor="w", justify="left"
        )
        self.guide_label.pack(anchor="w", padx=14, pady=(0, 12))

        # footer
        ctk.CTkFrame(self.scroll, fg_color="transparent", height=20).pack()

    # ── Helpers ────────────────────────────────────────────────────────────

    def _divider(self, parent):
        ctk.CTkFrame(parent, height=1, fg_color=BORDER).pack(fill="x", padx=20, pady=(12, 0))

    def _set_loading(self, *widgets, loading=True):
        for w in widgets:
            w.configure(state="disabled" if loading else "normal")

    def _pulse_on_click(self, widget):
        """Brief gold border flash when a dropdown is clicked."""
        try:
            original = widget.cget("border_color")
        except Exception:
            original = BORDER
        try:
            widget.configure(border_color=GOLD)
            self.after(120, lambda: widget.configure(border_color="#665533"))
            self.after(240, lambda: widget.configure(border_color=original))
        except Exception:
            pass

    # ── Toggle external IP visibility ───────────────────────────────────────

    def _toggle_pub_ip(self):
        if self._pub_ip_visible:
            self.lbl_pub_ip.pack_forget()
            self.lbl_pub_ip_hidden.pack(side="left")
            self.btn_view_addr.configure(text="View Address")
            self._pub_ip_visible = False
        else:
            self.lbl_pub_ip_hidden.pack_forget()
            self.lbl_pub_ip.configure(text=self.public_ip)
            self.lbl_pub_ip.pack(side="left")
            self.btn_view_addr.configure(text="Hide Address")
            self._pub_ip_visible = True

    # ── Segment click ───────────────────────────────────────────────────────

    def _on_segment(self, value):
        self.game_version.set(value)
        # update button colors — active gets gold bg, others go transparent
        for val, btn in self._seg_btn_refs.items():
            if val == value:
                btn.configure(fg_color=GOLD, text_color=BG, hover_color=GOLD_HOV)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_MUTED, hover_color="#333333")

        if value == "java":
            self.custom_port.set("25565")
            self.protocol_choice.set("TCP")
            self.port_entry.configure(state="disabled")
            self.proto_menu.configure(state="disabled")
        elif value == "bedrock":
            self.custom_port.set("19132")
            self.protocol_choice.set("UDP")
            self.port_entry.configure(state="disabled")
            self.proto_menu.configure(state="disabled")
        else:
            self.port_entry.configure(state="normal")
            self.proto_menu.configure(state="normal")

    def _set_window_icon(self):
        """Generate a gold-on-dark 'P' icon and set it as the window icon."""
        try:
            from PIL import Image, ImageDraw, ImageFont
            import tempfile

            size = 64
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)

            # Dark rounded background
            r = 12
            draw.rounded_rectangle([2, 2, size - 2, size - 2], radius=r,
                                    fill=(17, 17, 17, 255), outline=(200, 169, 110, 255), width=2)

            # Gold "P" text
            try:
                font = ImageFont.truetype("segoeui.ttf", 36)
            except Exception:
                try:
                    font = ImageFont.truetype("arial.ttf", 36)
                except Exception:
                    font = ImageFont.load_default()

            bbox = draw.textbbox((0, 0), "P", font=font)
            tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
            x = (size - tw) // 2 - bbox[0]
            y = (size - th) // 2 - bbox[1] - 2
            draw.text((x, y), "P", fill=(200, 169, 110, 255), font=font)

            ico_path = os.path.join(tempfile.gettempdir(), "_portify_icon.ico")
            img.save(ico_path, format="ICO", sizes=[(32, 32), (64, 64)])
            self.iconbitmap(ico_path)
        except Exception:
            pass

    # ── Manual guide ──────────────────────────────────────────────────────

    def _show_manual_guide(self, brand):
        ip = self.local_ip
        guides = {
            "TP-Link": (
                f"1. Visit http://192.168.0.1 (or 192.168.1.1)\n"
                f"2. Log in (default: admin / admin)\n"
                f"3. Advanced → NAT Forwarding → Virtual Servers → Add\n"
                f"4. Name: Minecraft  |  Port: [your port]\n"
                f"   Device IP: {ip}  |  Protocol: TCP or UDP\n"
                f"5. Save."
            ),
            "Netgear": (
                f"1. Visit http://192.168.1.1 (or routerlogin.net)\n"
                f"2. Log in (default: admin / password)\n"
                f"3. Advanced → Port Forwarding → Add Custom Service\n"
                f"4. Name: Minecraft  |  Port: [your port]\n"
                f"   Internal IP: {ip}  |  Protocol: TCP/UDP\n"
                f"5. Apply."
            ),
            "ASUS": (
                f"1. Visit http://192.168.1.1 (or router.asus.com)\n"
                f"2. Log in with admin credentials\n"
                f"3. WAN → Virtual Server / Port Forwarding\n"
                f"4. Enable → Add profile\n"
                f"5. Name: Minecraft  |  Port: [your port]\n"
                f"   Local IP: {ip}  |  Protocol: BOTH\n"
                f"6. OK → Apply."
            ),
            "Linksys": (
                f"1. Visit http://192.168.1.1\n"
                f"2. Log in (default password: admin)\n"
                f"3. Security → Apps & Gaming → Single Port Forwarding\n"
                f"4. Add: Name: Minecraft\n"
                f"   Port: [your port]  |  Protocol: Both\n"
                f"   To IP: {ip}  |  Enable: ✓\n"
                f"5. Save."
            ),
        }
        text = guides.get(brand, "Select a brand to see instructions.")
        self.guide_label.configure(text=text, text_color=TEXT_MAIN,
                                    font=(FONT_MONO, 9), anchor="w", justify="left")

    # ── Network detection ─────────────────────────────────────────────────

    def _refresh(self):
        self.lbl_local_ip.configure(text="Detecting…")
        self.lbl_pub_ip.configure(text="")
        self._pub_ip_visible = False
        self.lbl_pub_ip_hidden.pack(side="left")
        self.btn_view_addr.configure(text="View Address")
        self.status_dot.configure(text_color=WARNING)
        self.status_label.configure(text="Checking router…", text_color=TEXT_MUTED)
        self.cgnat_frame.pack_forget()
        self._set_loading(self.btn_refresh, loading=True)
        self._start_detection()

    def _start_detection(self):
        threading.Thread(target=self._detect_thread, daemon=True).start()
        self._animate_dots()

    def _animate_dots(self):
        if self._dot_animating:
            return
        self._dot_animating = True

        def loop():
            txt = self.status_label.cget("text")
            if "Checking" in txt or "Detecting" in txt:
                if txt.endswith("…") or txt.endswith("..."):
                    base = txt.rstrip(".").rstrip("…")
                    self.status_label.configure(text=base)
                else:
                    self.status_label.configure(text=txt + ".")
                self.after(500, loop)
            else:
                self._dot_animating = False
        loop()

    def _detect_thread(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self.local_ip = "127.0.0.1"
        self.after(0, lambda: self.lbl_local_ip.configure(text=self.local_ip))

        public_ip = None
        for url in ["https://api.ipify.org", "https://ifconfig.me/ip"]:
            try:
                res = requests.get(url, timeout=5)
                if res.status_code == 200:
                    public_ip = res.text.strip()
                    break
            except Exception:
                pass

        self.public_ip = public_ip or "Could not fetch"
        self.after(0, lambda: self.lbl_pub_ip.configure(text=self.public_ip))

        success = self.upnp_mgr.discover()
        if success:
            name = self.upnp_mgr._router_name or "Router"
            if len(name) > 28:
                name = name[:26] + "…"
            self.after(0, lambda: self._set_status("success", f"Connected — {name}"))
            self._check_nat()
        else:
            self.after(0, lambda: self._set_status("error", "No UPnP device found"))

        self.after(0, lambda: self._set_loading(self.btn_refresh, loading=False))

    def _set_status(self, state, message):
        color = SUCCESS if state == "success" else (DANGER if state == "error" else WARNING)
        self.status_dot.configure(text_color=color)
        self.status_label.configure(text=message,
                                     text_color=TEXT_MAIN if state == "success" else TEXT_MUTED)

    def _check_nat(self):
        router_ip = self.upnp_mgr.router_external_ip
        public_ip = self.public_ip
        if not router_ip or not public_ip or public_ip == "Could not fetch":
            return
        if router_ip == public_ip:
            return

        try:
            ip_obj = ipaddress.ip_address(router_ip)
            is_private = ip_obj.is_private
            is_cgnat = ip_obj in ipaddress.ip_network("100.64.0.0/10")
        except Exception:
            return

        if is_cgnat:
            text = ("Carrier-Grade NAT detected. Your ISP shares IP addresses, "
                    "which blocks standard port forwarding. Use Playit.gg or ngrok.")
        elif is_private:
            text = ("Double NAT detected. Your router is behind another modem/router. "
                    "Set the ISP modem to Bridge Mode.")
        else:
            text = ("Router IP doesn't match your public IP. "
                    "If using a VPN, disable it.")

        self.after(0, lambda: self._show_cgnat(text))

    def _show_cgnat(self, text):
        self.cgnat_desc.configure(text=text)
        self.cgnat_frame.pack(fill="x", padx=20, pady=(10, 0),
                               before=self.scroll.winfo_children()[3])

    # ── Port forwarding ────────────────────────────────────────────────────

    def _start_loading_animation(self):
        """Animate the button text with random dots while loading."""
        import random
        if self._loading_timer:
            self.after_cancel(self._loading_timer)
        dots = random.randint(1, 3)
        text = "Forwarding" + "." * dots
        try:
            self.btn_forward.configure(text=text)
        except Exception:
            pass
        self._loading_timer = self.after(400, self._start_loading_animation)

    def _stop_loading_animation(self):
        if self._loading_timer:
            self.after_cancel(self._loading_timer)
            self._loading_timer = None

    def _on_forward(self):
        port_str = self.custom_port.get().strip()
        if not port_str.isdigit():
            self.toast.show("Enter a valid numeric port.", "error")
            return
        port = int(port_str)
        if port < 1 or port > 65535:
            self.toast.show("Port must be 1–65535.", "error")
            return

        protocol = self.protocol_choice.get()
        protos = ["TCP", "UDP"] if "Both" in protocol else [protocol]

        # Ask for admin if not already elevated
        if not is_admin():
            import tkinter.messagebox as mbox
            result = mbox.askyesno(
                "Administrator Privileges",
                "Portify needs administrator privileges to add firewall rules.\n\n"
                "Without admin, UPnP port forwarding still works but the Windows "
                "Firewall may block connections.\n\n"
                "Restart as administrator?",
                icon="warning",
            )
            if result:
                self._elevate_and_restart()
                return

        self.btn_forward.configure(state="disabled", text="Forwarding…")
        self._keep_btn_black(self.btn_forward)
        self._start_loading_animation()
        self.forward_status.configure(text="", text_color=TEXT_DIM)
        threading.Thread(target=self._forward_thread, args=(port, protos), daemon=True).start()

    def _elevate_and_restart(self):
        """Restart this app as administrator via UAC prompt."""
        try:
            import ctypes
            exe = sys.executable
            if exe.endswith("python.exe"):
                exe = exe.replace("python.exe", "pythonw.exe")
            elif exe.lower().endswith("python"):
                exe += "w"
            script = os.path.abspath(sys.argv[0]) if sys.argv else ""
            params = f'"{script}"' if script else ""
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if int(ret) > 32:
                self.destroy()
                sys.exit(0)
        except Exception as e:
            log(f"Elevation failed: {e}")

    def _forward_thread(self, port, protocols):
        log(f"Forwarding port {port} ({', '.join(protocols)})...")

        # Discover UPnP if not already done
        if not self.upnp_mgr.discovered:
            log("Discovering UPnP router...")
            if not self.upnp_mgr.discover():
                err = self.upnp_mgr.discovery_error or "Unknown error"
                log(f"Discovery failed: {err}")
                self.after(0, lambda: self._forward_done(
                    False, f"Router not found: {err}"))
                return
            log(f"Router found: {self.upnp_mgr._router_name}")

        ok_count = 0
        errors = []
        for proto in protocols:
            if (port, proto) in self.upnp_mgr.active_forwards:
                log(f"{port}/{proto} already forwarded")
                ok_count += 1
                continue
            log(f"Adding mapping for {port}/{proto}...")
            ok, err = self.upnp_mgr.add_mapping(port, proto, self.local_ip)
            if ok:
                log(f"{port}/{proto} opened successfully")
                ok_count += 1
            else:
                log(f"{port}/{proto} failed: {err}")
                errors.append(f"{proto}: {err}")

        if ok_count > 0:
            msg = f"Port {port} opened successfully!"
            if errors:
                msg += f" (partial: {', '.join(errors)})"
            if not is_admin():
                msg += " (no firewall rule — run as admin for full access)"
            self.after(0, lambda m=msg: self._forward_done(True, m))
        else:
            self.after(0, lambda e=', '.join(errors): self._forward_done(False, f"Failed: {e}"))

    def _keep_btn_black(self, btn):
        """Force button label text to black. Called once; reschedules only while
        the button still shows a non-default colour (i.e. during forwarding)."""
        try:
            btn._text_label.configure(fg=BG)
        except Exception:
            pass
        # Only keep polling while the button is NOT gold (i.e. during loading/success)
        try:
            cur_color = btn.cget("fg_color")
        except Exception:
            return
        if cur_color != GOLD:
            btn.after(200, lambda: self._keep_btn_black(btn))

    def _reset_button(self):
        """Reset button to default state."""
        # Stop the keep_black polling loop by letting it see GOLD next tick
        self.btn_forward.configure(state="normal", text="Open Connection Port",
                                   fg_color=GOLD, hover_color=GOLD_HOV)
        try:
            self.btn_forward._text_label.configure(fg=BG)
        except Exception:
            pass
        # Force one more black-text tick then let the loop exit naturally
        self.btn_forward.after(250, lambda: self._finalise_reset())

    def _finalise_reset(self):
        """One-shot: set text colour to black, then stop polling."""
        try:
            self.btn_forward._text_label.configure(fg=BG)
        except Exception:
            pass

    def _forward_done(self, success, message):
        self._stop_loading_animation()
        log(f"_forward_done: success={success}, msg={message}")
        if success:
            self.btn_forward.configure(state="normal", text="Port Open ✓",
                                       fg_color=SUCCESS, hover_color="#3d8b40")
            try:
                self.btn_forward._text_label.configure(fg="#ffffff")
            except Exception:
                pass
            self.forward_status.configure(text=message, text_color=SUCCESS)
            try:
                self._update_active_ui()
            except Exception as e:
                log(f"_update_active_ui error: {e}")
            # Scroll to show active ports after UI updates
            try:
                self.scroll.update_idletasks()
                self.scroll._parent_canvas.yview_moveto(1.0)
            except Exception as e:
                log(f"scroll error: {e}")
            # Schedule button reset BEFORE toast — toast must not block reset
            self.after(4000, self._reset_button)
            try:
                self.toast.show(message, "success", duration=6000)
            except Exception as e:
                log(f"toast error: {e}")
        else:
            self.btn_forward.configure(state="normal", text="Retry Forwarding",
                                       fg_color=GOLD, hover_color=GOLD_HOV)
            try:
                self.btn_forward._text_label.configure(fg=BG)
            except Exception:
                pass
            self.forward_status.configure(text=message, text_color=DANGER)
            # Schedule button reset BEFORE toast — toast must not block reset
            self.after(6000, self._reset_button)
            try:
                self.toast.show(message, "error", duration=6000)
            except Exception as e:
                log(f"toast error: {e}")

    # ── Active ports UI ────────────────────────────────────────────────────

    def _update_active_ui(self):
        try:
            for w in self.active_container.winfo_children():
                w.destroy()
        except Exception as e:
            log(f"_update_active_ui destroy error: {e}")
            return

        forwards = self.upnp_mgr.active_forwards
        log(f"_update_active_ui: {len(forwards)} forwards: {list(forwards.keys())}")
        if not forwards:
            try:
                self.no_ports_label = ctk.CTkLabel(
                    self.active_container,
                    text="No active forwards yet.\nOpen a port above to get started.",
                    text_color=TEXT_DIM, font=(FONT, 10), pady=16
                )
                self.no_ports_label.pack(fill="x")
                self.active_warn.pack_forget()
            except Exception as e:
                log(f"_update_active_ui empty error: {e}")
            return

        try:
            self.active_warn.pack(fill="x", padx=14, pady=(0, 10))
        except Exception as e:
            log(f"_update_active_ui warn pack error: {e}")

        bp_colors = {"TCP": ("#152030", SUCCESS), "UDP": ("#2a1525", WARNING)}

        for (port, proto), desc in forwards.items():
            row = ctk.CTkFrame(self.active_container, fg_color="transparent")
            row.pack(fill="x", pady=(0, 3))

            ctk.CTkLabel(row, text=str(port), text_color=TEXT_MAIN,
                         font=(FONT_MONO, 13, "bold"), width=60, anchor="w").pack(side="left")

            bg_c, txt_c = bp_colors.get(proto, (OVERLAY, TEXT_MUTED))
            ctk.CTkLabel(row, text=proto, text_color=txt_c,
                         fg_color=bg_c, corner_radius=5,
                         font=(FONT, 8, "bold"), width=40, height=20).pack(side="left", padx=(6, 0))

            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right")

            ctk.CTkButton(btns, text="Copy", width=46, height=24,
                          fg_color="transparent", hover_color=CARD_HOVER,
                          text_color=TEXT_MUTED, corner_radius=4,
                          font=(FONT, 9),
                          command=lambda p=port: self._copy_addr(p)).pack(side="left", padx=(0, 3))

            test_btn = ctk.CTkButton(btns, text="Test", width=46, height=24,
                          fg_color="transparent", hover_color=CARD_HOVER,
                          text_color=SUCCESS, corner_radius=4,
                          font=(FONT, 9))
            test_btn.configure(command=lambda p=port, b=test_btn: self._test_port(p, b))
            test_btn.pack(side="left", padx=(0, 3))

            ctk.CTkButton(btns, text="Remove", width=56, height=24,
                          fg_color="transparent", hover_color="#221515",
                          text_color=DANGER, corner_radius=4,
                          font=(FONT, 9),
                          command=lambda p=port, pr=proto: self._remove_port(p, pr)).pack(side="left")

            ctk.CTkFrame(self.active_container, height=1, fg_color=BORDER).pack(fill="x", pady=(3, 0))

    def _copy_addr(self, port):
        if self.public_ip in ["Detecting…", "Could not fetch"]:
            self.toast.show("Still detecting public IP…", "warning")
            return
        addr = f"{self.public_ip}:{port}"
        self.clipboard_clear()
        self.clipboard_append(addr)
        self.toast.show(f"Copied {addr}", "success")

    def _test_port(self, port, btn):
        """Test if a port is reachable. `btn` is the Test button widget."""
        btn.configure(state="disabled", text="…")
        self.toast.show(f"Testing port {port}…", "info", duration=3000)
        threading.Thread(target=self._test_thread, args=(port, btn), daemon=True).start()

    def _test_thread(self, port, btn):
        # Make sure we have a public IP
        if self.public_ip in ["Detecting…", "Could not fetch"]:
            try:
                res = requests.get("https://api.ipify.org", timeout=5)
                if res.status_code == 200:
                    self.public_ip = res.text.strip()
                    self.after(0, lambda: self.lbl_pub_ip.configure(text=self.public_ip))
            except Exception:
                pass
        if self.public_ip in ["Detecting…", "Could not fetch"]:
            self.after(0, lambda: self._test_result(None, "Could not determine public IP.", btn))
            return

        # Strategy: TCP connect is fastest (instant for open, ~2s for closed).
        # Try it first. If it fails (port closed), confirm with HTTP API.
        is_open = None

        # Step 1: Quick TCP connect (2s timeout — fast fail for closed ports)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            r = sock.connect_ex((self.public_ip, port))
            sock.close()
            if r == 0:
                is_open = True
            # If r != 0, port might be filtered (not just closed), so check HTTP too
        except Exception:
            pass

        # Step 2: If TCP was successful, confirm with HTTP API in parallel
        if is_open is True:
            http_result = [None]
            def check_http():
                try:
                    url = f"https://portchecker.io/api/{self.public_ip}/{port}"
                    res = requests.get(url, timeout=3)
                    if res.status_code == 200:
                        text = res.text.strip().lower()
                        if "true" in text or "open" in text:
                            http_result[0] = True
                        elif "false" in text or "closed" in text:
                            http_result[0] = False
                except Exception:
                    pass
            t = threading.Thread(target=check_http, daemon=True)
            t.start()
            t.join(timeout=4)  # wait max 4s for HTTP confirmation
            # If HTTP also says open (or didn't respond), trust TCP
            if http_result[0] is not False:
                is_open = True
            else:
                is_open = False  # HTTP disagrees — trust HTTP

        # Step 3: If TCP was inconclusive, try HTTP
        if is_open is None:
            try:
                url = f"https://portchecker.io/api/{self.public_ip}/{port}"
                res = requests.get(url, timeout=4)
                if res.status_code == 200:
                    text = res.text.strip().lower()
                    if "true" in text or "open" in text:
                        is_open = True
                    elif "false" in text or "closed" in text:
                        is_open = False
            except Exception:
                pass

        # Step 4: If everything failed, try one more TCP with longer timeout
        if is_open is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                r = sock.connect_ex((self.public_ip, port))
                sock.close()
                is_open = (r == 0)
            except Exception:
                pass

        self.after(0, lambda: self._test_result(is_open, port, btn))

    def _test_result(self, is_open, extra, btn):
        try:
            btn.configure(state="normal", text="Test")
        except Exception:
            pass
        if is_open is True:
            self.toast.show(f"Port {extra} is OPEN! ✓", "success")
        elif is_open is False:
            self.toast.show(f"Port {extra} is CLOSED. Make sure your server is running.", "warning")
        else:
            self.toast.show(f"Test failed: {extra}", "error")

    def _remove_port(self, port, protocol):
        threading.Thread(target=self._remove_thread, args=(port, protocol), daemon=True).start()

    def _remove_thread(self, port, protocol):
        ok, err = self.upnp_mgr.delete_mapping(port, protocol)
        if ok:
            self.after(0, lambda: self.toast.show(f"Closed {port}/{protocol}", "success"))
        else:
            self.after(0, lambda: self.toast.show(f"Failed: {err}", "error"))
        self.after(0, self._update_active_ui)

    # ── Exit ───────────────────────────────────────────────────────────────

    def _on_exit(self):
        # Clean up UPnP mappings on exit (no UAC prompts — just SOAP calls)
        try:
            if self.upnp_mgr.discovered:
                self.upnp_mgr.clear_all()
        except Exception:
            pass
        self.destroy()

    def _cleanup_atexit(self):
        pass


# ── Entry ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    # Check if user explicitly requested admin (right-click → Run as administrator)
    # If not admin, app still runs — firewall features just won't work
    app = PortifyApp()
    app.mainloop()
