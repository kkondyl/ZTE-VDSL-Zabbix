#!/usr/bin/env python3
"""
ZTE H267A DSL stats fetcher (RPi-friendly)

- Logs in via tokened form (sha256(password + token)) or accepts a pre-hashed hex.
- Warms up common pages (like the browser does) to avoid stub/404 responses.
- Fetches DSL stats, handling <ajax_response_xml_root> with <ParaName>/<ParaValue> pairs.
- Normalizes units (kbps -> Mbps, tenths dB -> dB) and emits JSON.

Dependencies (on Raspberry Pi OS / Debian):
  sudo apt update
  sudo apt install -y python3 python3-venv python3-pip python3-lxml libxml2-dev libxslt1-dev jq curl
  # inside a venv (recommended):
  pip install requests beautifulsoup4

Usage:
  python3 zte_vdsl.py -H 192.168.2.1 -u admin --pretty
  python3 zte_vdsl.py -H 192.168.2.1 -u admin -p 'PLAIN_PASSWORD' --pretty
  # If your unit needs a fixed SHA256 hex instead of tokened password:
  python3 zte_vdsl.py -H 192.168.2.1 -u admin --prehashed 'e3b0c442...' --pretty
"""

import hashlib
import json
import time
from typing import List, Dict, Optional, Tuple

import requests
from bs4 import BeautifulSoup


class ZTEH267A:
    # Endpoints seen on H267A (and compatible ZTE WebUI variants)
    WARMUP_PATHS: List[str] = [
        "/",  # set cookies, etc.
        "/getpage.lua?pid=123&nextpage=Internet_AdminInternetStatus_DSL_t.lp&Menu3Location=0",
    ]

    # Pages that commonly return DSL info (HTML/XML/ajax XML)
    DATA_PATHS: List[str] = [
        "/common_page/internet_dsl_interface_lua.lua",
    ]


    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        prehashed_password_hex: Optional[str] = None,
        timeout: int = 6,
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.prehashed = prehashed_password_hex
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "DNT": "1",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        self.sid = None
        self.ip_address = ""

    # --------- helpers ---------
    def _url(self, path: str) -> str:
        return f"http://{self.host}{path}"

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    # --------- token + login ---------
    def fetch_token(self) -> str:
        """
        Fetch token from login token page.
        Token can be under <Frm_Logintoken> or the whole text may be wrapped under <ajax_response_xml_root>.
        """
        url = self._url("/function_module/login_module/login_page/logintoken_lua.lua")
        r = self.session.get(url, timeout=self.timeout)
        soup = BeautifulSoup(r.content, "lxml")

        # Classic tag
        tag = soup.find("Frm_Logintoken")
        if tag and tag.text.strip():
            return tag.text.strip()

        # H267A often returns token directly under root text or inside ajax wrapper
        root = soup.find("ajax_response_xml_root")
        if root and root.text.strip():
            return root.text.strip()

        # Fallback: page text
        text = soup.get_text(strip=True)
        return text or ""

    def compute_password_hex(self, token: str) -> str:
        """
        If prehashed hex provided -> use it.
        Else if token present -> sha256(plaintext + token).
        Else fallback to sha256(plaintext).
        """
        if self.prehashed:
            return self.prehashed

        if token:
            h = hashlib.sha256()
            h.update((self.password + token).encode())
            return h.hexdigest()

        h = hashlib.sha256()
        h.update(self.password.encode())
        return h.hexdigest()

    def login(self) -> bool:
        # initial GET to set cookies
        self.session.get(self._url("/"), timeout=self.timeout)
        token = self.fetch_token()
        pass_hex = self.compute_password_hex(token)

        # Login form
        payload = {"Username": self.username, "Password": pass_hex, "action": "login"}
        r = self.session.post(self._url("/"), data=payload, allow_redirects=False, timeout=self.timeout)

        # Read SID cookie if any
        self.sid = self.session.cookies.get("SID")
        return r.status_code in (200, 302) or bool(self.sid)

    # --------- warmup & probing ---------
    def _warmup(self, pause: float = 0.12):
        for p in self.WARMUP_PATHS:
            url = self._url(p)
            try:
                self.session.get(url, timeout=self.timeout)
            except Exception:
                pass
            time.sleep(pause)

    def _probe_data_endpoints(self, prime_pause: float = 0.03) -> Optional[requests.Response]:
        for p in self.DATA_PATHS:
            url = self._url(p)
            # add cache buster
            url += ("&" if "?" in p else "?") + f"_={self._now_ms()}"
            try:
                r = self.session.get(url, timeout=self.timeout)
            except Exception:
                continue
            ctype = r.headers.get("Content-Type", "")
            body = r.content or b""

            # Heuristics: many WebUIs return XML-like or ajax XML wrapped in HTML content-type
            if b"<ajax_response_xml_root>" in body or b"<Instance>" in body:
                return r

            if "xml" in ctype.lower():
                return r

            # Accept larger HTML pages containing DSL keywords
            if "html" in ctype.lower() and len(body) > 1024:
                lower = body.lower()
                if any(k in lower for k in (b"dsl", b"snr", b"attenuation", b"linerate", b"rate", b"vdsl", b"g.993")):
                    return r

            time.sleep(prime_pause)
        return None


    # --------- parsing helpers ---------
    @staticmethod
    def _to_float_tenths(val: str):
        try:
            return round(int(val) / 10.0, 1)
        except Exception:
            try:
                return float(val)
            except Exception:
                return val

    @staticmethod
    def _to_int(val: str):
        try:
            return int(val)
        except Exception:
            return val

    @staticmethod
    def parse_zte_para_pairs(instance_tag) -> Tuple[Dict[str, str], Dict[str, object]]:
        """
        Parse <Instance><ParaName>...<ParaValue>...</ParaValue> pairs into:
          - raw dict
          - normalized dict with units/converted numbers
        """
        names = [t.get_text(strip=True) for t in instance_tag.find_all("paraname")]
        values = [t.get_text(strip=True) for t in instance_tag.find_all("paravalue")]
        raw = {
            (names[i] if i < len(values) else f"Field{i}").strip(): values[i]
            for i in range(min(len(names), len(values)))
        }

        norm: Dict[str, object] = {}

        # rates (kbps -> Mbps)
        for k_src, k_dst in [
            ("Upstream_current_rate", "up_current_mbps"),
            ("Downstream_current_rate", "down_current_mbps"),
            ("Upstream_max_rate", "up_max_mbps"),
            ("Downstream_max_rate", "down_max_mbps"),
        ]:
            if k_src in raw:
                v = ZTEH267A._to_int(raw[k_src])
                norm[k_dst] = round(v / 1000.0, 3) if isinstance(v, int) else v

        # SNR/attenuation/power in tenths
        for k_src, k_dst in [
            ("Upstream_noise_margin", "up_snr_db"),
            ("Downstream_noise_margin", "down_snr_db"),
            ("Upstream_attenuation", "up_attn_db"),
            ("Downstream_attenuation", "down_attn_db"),
            ("Upstream_power", "up_power_dbm"),
            ("Downstream_power", "down_power_dbm"),
        ]:
            if k_src in raw:
                norm[k_dst] = ZTEH267A._to_float_tenths(raw[k_src])

        # Interleave depth/delay
        for k_src, k_dst in [
            ("UpInterleaveDepth", "up_interleave_depth"),
            ("DownInterleavedepth", "down_interleave_depth"),
            ("UpInterleaveDelay", "up_delay_ms"),
            ("DownInterleaveDelay", "down_delay_ms"),
        ]:
            if k_src in raw:
                norm[k_dst] = ZTEH267A._to_int(raw[k_src])

        # Errors, profile, link info
        for k_src, k_dst in [
            ("UpCrc_errors", "up_crc"),
            ("DownCrc_errors", "down_crc"),
            ("Fec_errors", "fec_ds"),
            ("Atuc_fec_errors", "fec_us"),
            ("Status", "status"),
            ("CurrentProfile", "profile"),
            ("Module_type", "modulation"),
            ("Data_path", "data_path"),
            ("tLinkEncapsulationUsed", "link_encap"),
            ("Showtime_start", "showtime_seconds"),
            ("LoopLength", "loop_length_m"),
            ("Enable", "enable"),
        ]:
            if k_src in raw:
                if k_dst in {"up_crc", "down_crc", "fec_ds", "fec_us", "showtime_seconds", "loop_length_m", "enable"}:
                    norm[k_dst] = ZTEH267A._to_int(raw[k_src])
                else:
                    norm[k_dst] = raw[k_src]

        return raw, norm

    def parse_generic_instances(self, soup: BeautifulSoup) -> Dict[str, Dict[str, str]]:
        """
        Fallback parser for pages returning multiple <instance> nodes with direct children tags.
        """
        out: Dict[str, Dict[str, str]] = {}
        instances = soup.find_all("instance")
        for idx, inst in enumerate(instances):
            # direct children map
            parsed: Dict[str, str] = {}
            for child in inst.find_all(recursive=False):
                key = (child.name or f"field{idx}").strip()
                parsed[key] = child.get_text(strip=True)
            keyname = parsed.get("Name") or parsed.get("IfName") or f"instance_{idx}"
            keyname = keyname.strip().lower().replace(" ", "_")
            if keyname in out:
                keyname = f"{keyname}_{idx}"
            out[keyname] = parsed
        return out

    # --------- main API ---------
    def get_stats(self) -> Dict[str, object]:
        if not self.login():
            raise RuntimeError("login failed (no SID or non-200 response)")

        self._warmup()

        resp = self._probe_data_endpoints()
        if resp is None:
            raise RuntimeError("no DSL payload found on data endpoints")

        ctype = resp.headers.get("Content-Type", "")
        body = resp.content
        result: Dict[str, object] = {"content_type": ctype, "raw": body.decode(errors="replace")}

        soup = BeautifulSoup(body, "lxml")

        # Case A: ajax_response_xml_root with ParaName/ParaValue pairs (typical for H267A DSL)
        root = soup.find("ajax_response_xml_root")
        if root:
            dsl_container = root.find("obj_dslinterface_id")
            inst = dsl_container.find("instance") if dsl_container else None
            if inst:
                raw_pairs, norm = self.parse_zte_para_pairs(inst)
                result.setdefault("parsed", {})
                result["parsed"]["dsl_raw"] = raw_pairs
                result["parsed"]["dsl"] = norm

        # Case B: generic <instance> nodes
        if "parsed" not in result or "dsl" not in result["parsed"]:
            generic = self.parse_generic_instances(soup)
            if generic:
                result.setdefault("parsed", {})
                result["parsed"].update(generic)


        return result


# ---------------- CLI ----------------
if __name__ == "__main__":
    import argparse
    import sys
    from getpass import getpass

    parser = argparse.ArgumentParser(description="Fetch DSL stats from ZTE H267A")
    parser.add_argument("--host", "-H", required=True, help="modem host or IP (e.g., 192.168.0.1)")
    parser.add_argument("--username", "-u", default="admin", help="login username (default: admin)")
    parser.add_argument("--password", "-p", help="plain password (omit to be prompted)")
    parser.add_argument(
        "--prehashed",
        help="optional pre-hashed password hex (sha256) if your unit expects a fixed hex",
    )
    parser.add_argument("--timeout", type=float, default=6.0, help="request timeout seconds (default 6)")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    if not args.password and not args.prehashed:
        # ask for plain password if prehashed is not supplied
        args.password = getpass("Password: ")

    try:
        modem = ZTEH267A(
            host=args.host,
            username=args.username,
            password=args.password or "",
            prehashed_password_hex=args.prehashed,
            timeout=int(args.timeout),
        )
        stats = modem.get_stats()
        out = {"ok": True, "data": stats}
        print(json.dumps(out, indent=2 if args.pretty else None))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(2)
