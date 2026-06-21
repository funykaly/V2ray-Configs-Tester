import argparse
import asyncio
import base64
import json
import os
import re
import sys
from urllib.parse import urlparse

try:
    from telethon import TelegramClient
    from telethon.errors import SessionPasswordNeededError
except Exception:
    TelegramClient = None
    SessionPasswordNeededError = Exception


URL_PATTERN = re.compile(
    r'(?i)(anytls|blackhole|block|custom|direct|dns|dokodemo-door|freedom|http|https|hy2|hy|hysteria2|hysteria|json|juicity|mixed|naive|redirect|selector|shadowtls|ssh|ssr|ss|socks5|socks4a|socks4|socks|tap|tailscale|tor|trojan|tproxy|tun|tuic|urltest|vless|vmess|wg|wireguard)://[^\s"\'<>]+'
)
BASE64_ONLY = re.compile(r'^[A-Za-z0-9+/_=\-\s\r\n]+$')


def load_config():
    path = "config.json"
    if not os.path.exists(path):
        return {
            "telegram": {
                "api_id": 0,
                "api_hash": "",
                "session_name": "sentinel_session",
            }
        }
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def decode_base64(value: str) -> str:
    clean = value.strip().replace("-", "+").replace("_", "/").replace("\n", "").replace("\r", "").replace(" ", "")
    while len(clean) % 4 != 0:
        clean += "="
    try:
        return base64.b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        return value


def find_proxy_links(content: str):
    decoded = content
    trimmed = content.strip()
    if "://" not in trimmed and BASE64_ONLY.match(trimmed):
        plain = decode_base64(trimmed)
        if "://" in plain:
            decoded = plain
    links = []
    for match in URL_PATTERN.finditer(decoded):
        value = clean_link(match.group(0))
        if value and should_keep_link(value):
            links.append(value)
    return list(dict.fromkeys(links))


def clean_link(value: str) -> str:
    value = value.strip()
    value = value.strip("\"'`[]{}<>")
    while value.endswith((")", ",", ";", ".", "`")):
        value = value[:-1].rstrip()
    return value


def should_keep_link(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return True
    host = (parsed.hostname or "").lower().strip()
    if host in {"t.me", "www.t.me", "telegram.me", "www.telegram.me", "telegram.dog", "www.telegram.dog"}:
        return False
    if parsed.scheme.lower() in {"http", "https", "socks", "socks4", "socks4a", "socks5"} and not parsed.port:
        return False
    return True


def extract_links(content: str):
    return find_proxy_links(content)


async def make_client():
    cfg = load_config().get("telegram", {})
    api_id = int(cfg.get("api_id") or 0)
    api_hash = str(cfg.get("api_hash") or "").strip()
    session_name = str(cfg.get("session_name") or "sentinel_session").strip()
    if TelegramClient is None:
        return None, "telethon-not-installed"
    if not api_id or not api_hash:
        return None, "telegram-api-config-missing"
    client = TelegramClient(session_name, api_id, api_hash)
    await client.connect()
    if not await client.is_user_authorized():
        await client.disconnect()
        return None, "telegram-session-not-authorized"
    return client, ""


async def command_health(channel: str):
    client, err = await make_client()
    if client is None:
        print(json.dumps({"ok": False, "authorized": False, "detail": err}))
        return 1
    try:
        me = await client.get_me()
        detail = f"authorized as {getattr(me, 'username', None) or getattr(me, 'first_name', 'unknown')}"
        if channel:
            msgs = await client.get_messages(channel, limit=1)
            detail += f"; channel={channel}; messages={len(msgs) if msgs else 0}"
        print(json.dumps({"ok": True, "authorized": True, "detail": detail}))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "authorized": False, "detail": str(exc)}))
        return 2
    finally:
        await client.disconnect()


async def command_dump(channel: str, limit: int):
    client, err = await make_client()
    if client is None:
        print(json.dumps({"ok": False, "detail": err}))
        return 1
    try:
        messages = await client.get_messages(channel, limit=limit)
        links = []
        for msg in messages:
            text = getattr(msg, "text", None)
            if text:
                links.extend(extract_links(text))
        sys.stdout.write("\n".join(dict.fromkeys(links)))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}))
        return 2
    finally:
        await client.disconnect()


async def command_login():
    cfg = load_config().get("telegram", {})
    api_id = int(cfg.get("api_id") or 0)
    api_hash = str(cfg.get("api_hash") or "").strip()
    session_name = str(cfg.get("session_name") or "sentinel_session").strip()
    if TelegramClient is None:
        print("Telethon is not installed.")
        return 1
    client = TelegramClient(session_name, api_id, api_hash)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            sys.stdout.write("Phone (+989...): ")
            sys.stdout.flush()
            phone = sys.stdin.readline().strip()
            if not phone:
                print("Phone number is required.")
                return 1
            await client.send_code_request(phone)
            sys.stdout.write("Code: ")
            sys.stdout.flush()
            code = sys.stdin.readline().strip()
            try:
                await client.sign_in(phone, code)
            except SessionPasswordNeededError:
                sys.stdout.write("2FA Password: ")
                sys.stdout.flush()
                password = sys.stdin.readline().strip()
                await client.sign_in(password=password)
        me = await client.get_me()
        print(f"Telegram login OK: {getattr(me, 'username', None) or getattr(me, 'first_name', 'unknown')}")
        return 0
    finally:
        await client.disconnect()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", dest="health", default="")
    parser.add_argument("--dump", dest="dump", default="")
    parser.add_argument("--limit", dest="limit", type=int, default=80)
    parser.add_argument("--login", dest="login", action="store_true")
    args = parser.parse_args()

    if args.login:
        return asyncio.run(command_login())
    if args.dump:
        return asyncio.run(command_dump(args.dump, args.limit))
    return asyncio.run(command_health(args.health))


if __name__ == "__main__":
    raise SystemExit(main())
