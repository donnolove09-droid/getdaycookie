# -*- coding: utf-8 -*-
"""extractor.py — Playwright login + auto IP detect."""

import io
import os
import json
import requests
import pyzipper
from datetime import datetime
from playwright.async_api import async_playwright


SITES = {
    "facebook": {
        "url": "https://www.facebook.com/login",
        "user_sel": 'input[name="email"]',
        "pass_sel": 'input[name="pass"]',
        "submit_sel": 'button[name="login"]',
    },
    "tiktok": {
        "url": "https://www.tiktok.com/login/phone-or-email/email",
        "user_sel": 'input[name="username"]',
        "pass_sel": 'input[type="password"]',
        "submit_sel": 'button[type="submit"]',
    },
    "instagram": {
        "url": "https://www.instagram.com/accounts/login/",
        "user_sel": 'input[name="username"]',
        "pass_sel": 'input[name="password"]',
        "submit_sel": 'button[type="submit"]',
    },
}

DC_KEYWORDS = [
    "amazon", "aws", "google", "gcp", "microsoft", "azure",
    "digitalocean", "render", "ovh", "hetzner", "linode",
    "vultr", "cloudflare", "fastly", "akamai", "oracle",
]


def get_my_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return "unknown"


def get_ip_info(ip):
    try:
        d = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query",
            timeout=5
        ).json()
        if d.get("status") != "success":
            return {"ip": ip, "is_datacenter": True}
        isp = (d.get("isp") or "") + " " + (d.get("org") or "") + " " + (d.get("as") or "")
        return {
            "ip": ip,
            "country": d.get("country"),
            "city": d.get("city"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "is_datacenter": any(k in isp.lower() for k in DC_KEYWORDS),
        }
    except Exception:
        return {"ip": ip, "is_datacenter": True}


_RENDER_IP_CACHE = None


def get_render_ip_info(force=False):
    global _RENDER_IP_CACHE
    if _RENDER_IP_CACHE is None or force:
        ip = get_my_ip()
        info = get_ip_info(ip)
        info["ip"] = ip
        _RENDER_IP_CACHE = info
    return _RENDER_IP_CACHE


def parse_proxy(s):
    if not s:
        return None
    s = s.strip()
    if "://" not in s:
        s = "http://" + s
    scheme, rest = s.split("://", 1)
    scheme = scheme.lower()
    if scheme not in ("http", "https", "socks5", "socks4"):
        raise ValueError(f"Proxy scheme không hỗ trợ: {scheme}")
    proxy = {"server": f"{scheme}://{rest}"}
    if "@" in rest:
        creds, host = rest.rsplit("@", 1)
        if ":" in creds:
            u, p = creds.split(":", 1)
            proxy["username"] = u
            proxy["password"] = p
            proxy["server"] = f"{scheme}://{host}"
    return proxy


def mask_proxy(p):
    if not p:
        return ""
    if "@" in p:
        creds, host = p.rsplit("@", 1)
        if "://" in creds:
            scheme, userinfo = creds.split("://", 1)
            if ":" in userinfo:
                u, _ = userinfo.split(":", 1)
                return f"{scheme}://{u}:***@{host}"
        return f"***@{host}"
    return p


async def login_and_get_cookies(site, username, password,
                                 proxy_str=None, headless=True, timeout=60):
    """Login và trả cookie. Auto detect exit IP."""
    if site not in SITES:
        return {"success": False, "error": f"Site '{site}' không hỗ trợ."}

    proxy_cfg = None
    if proxy_str:
        try:
            proxy_cfg = parse_proxy(proxy_str)
        except Exception as e:
            return {"success": False, "error": f"Proxy lỗi: {e}"}

    cfg = SITES[site]
    result = {"success": False, "cookies": [], "error": None,
              "exit_info": None, "risk": "unknown"}

    async with async_playwright() as p:
        launch = {
            "headless": headless,
            "args": [
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
            ]
        }
        if proxy_cfg:
            launch["proxy"] = proxy_cfg

        browser = await p.chromium.launch(**launch)
        ctx = await browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"),
            viewport={"width": 1366, "height": 768},
            locale="vi-VN",
            timezone_id="Asia/Ho_Chi_Minh",
        )
        page = await ctx.new_page()

        try:
            # Detect exit IP
            try:
                await page.goto("https://api.ipify.org?format=json",
                                timeout=10000, wait_until="domcontentloaded")
                exit_ip = json.loads(await page.inner_text("body")).get("ip")
                info = get_ip_info(exit_ip)
                info["ip"] = exit_ip
                result["exit_info"] = info
                result["risk"] = "high" if info.get("is_datacenter") else "low"
            except Exception:
                result["exit_info"] = {"ip": "unknown", "is_datacenter": True}

            # Login
            await page.goto(cfg["url"], timeout=timeout * 1000,
                            wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
            await page.fill(cfg["user_sel"], username, timeout=15000)
            await page.wait_for_timeout(500)
            await page.fill(cfg["pass_sel"], password, timeout=15000)
            await page.wait_for_timeout(500)
            await page.click(cfg["submit_sel"], timeout=15000)
            await page.wait_for_timeout(8000)

            url = page.url
            if "login" not in url.lower() and "checkpoint" not in url.lower():
                result["success"] = True
                result["cookies"] = await ctx.cookies()
            else:
                result["error"] = f"Login fail / checkpoint. URL: {url}"

        except Exception as e:
            result["error"] = f"Playwright: {e}"
        finally:
            await browser.close()

    return result


def export_cookies_zip_bytes(cookies, site, username, password):
    """Tạo ZIP mã hóa AES với mật khẩu."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_user = "".join(c for c in username if c.isalnum() or c in "._-")[:30]
    fname = f"cheatgameos_{site}_{safe_user}_{ts}.zip"

    json_data = json.dumps({
        "meta": {
            "site": site, "username": username,
            "extracted_at": datetime.now().isoformat(),
            "total": len(cookies), "tool": "cheatgameos",
        },
        "cookies": cookies,
    }, ensure_ascii=False, indent=2).encode("utf-8")

    header_data = "; ".join(
        f"{c['name']}={c['value']}" for c in cookies
    ).encode("utf-8")

    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password .encode("utf-8"))
        zf.writestr(f"cookie_{site}_{safe_user}.json", json_data)
        zf.writestr(f"cookie_header_{site}.txt", header_data)

    return buf.getvalue(), fname
