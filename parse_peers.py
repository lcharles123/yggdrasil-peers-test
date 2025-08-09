import asyncio
import socket
import ssl
from typing import List, Tuple, Optional
from get_peers import get_peers, Peer
import logging as log
log.basicConfig(level=log.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
import websockets
from aioquic.asyncio import connect as aioquic_connect
from aioquic.quic.configuration import QuicConfiguration
from icmplib import async_ping
from tabulate import tabulate
import socks


def _test_tcp_sync(host: str, port: int, timeout: int = 5) -> Tuple[bool, str]:
    """Tests a raw TCP connection using blocking sockets."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"Successfully connected to {host}:{port} via TCP."
    except Exception as e:
        return False, f"Failed TCP connection to {host}:{port}: {e}"

def _test_tls_sync(host: str, port: int, timeout: int = 5) -> Tuple[bool, str]:
    """Tests a TLS-wrapped TCP connection."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return True, f"Successfully connected to {host}:{port} via TLS. Version: {ssock.version()}"
    except Exception as e:
        return False, f"Failed TLS connection to {host}:{port}: {e}"

async def _test_websocket_async(uri: str, timeout: int = 5) -> Tuple[bool, str]:
    """Tests a WebSocket (ws://) or Secure WebSocket (wss://) connection."""
    proto = uri.split(":", 1)[0].upper()
    try:
        async with websockets.connect(uri, open_timeout=timeout, family=socket.AF_INET6):
            return True, f"Successfully connected to {uri} via {proto}."
    except Exception as e:
        try:
            async with websockets.connect(uri, open_timeout=timeout, family=socket.AF_INET):
                return True, f"Successfully connected to {uri} via {proto}."
        except Exception as e:
            return False, f"Failed {proto} connection to {uri}: {e}"


async def _test_quic_async(host: str, port: int, timeout: int = 5) -> Tuple[bool, str]:
    """Tests a QUIC connection."""
    config = QuicConfiguration(is_client=True, verify_mode=False, idle_timeout=2.0)
    try:
        async with aioquic_connect(host, port, configuration=config):
            return True, f"Successfully established QUIC connection to {host}:{port}."
    except Exception as e:
        return False, f"Failed QUIC connection to {host}:{port}: {e}"


async def _ping(peer: Peer, timeout: int = 10) -> Peer:
    """
    Pings a single peer and prints the result. This is the core task
    that will be run in parallel for each peer.
    """
    if peer.network != 'internet':
        peer.ping_latency = 60000 # in case of tor or i2p
        return peer
    host = peer.addr
    if host[0] == '[': # unpack ipv6
        host = host[1:-1]
    try:
        # Perform the asynchronous ping
        result = await async_ping(host, count=3, timeout=timeout, family=6)
        
        if result.is_alive:
            # Print the latency in milliseconds, formatted to two decimal places
            log.debug(f"✅ SUCCESS: {peer.addr} -> {result.avg_rtt:.2f} ms")
            peer.ping_latency = int(result.avg_rtt)
            return peer
        else:
            raise Exception
    except:
        try:
            result = await async_ping(host, count=3, timeout=timeout, family=4)
            if result.is_alive:
                # Print the latency in milliseconds, formatted to two decimal places
                log.debug(f"✅ SUCCESS: {peer.addr} -> {result.avg_rtt:.2f} ms")
                peer.ping_latency = int(result.avg_rtt)
                return peer
            else:
                log.debug(f"❌ TIMEOUT: {peer.addr} -> No response within {timeout}s")
                return peer
        except Exception as e:
            # Catches other errors like name resolution failures or permission errors
            log.debug(f"🚫 ERROR:   {peer.addr} -> {e}")
            return peer

async def ping_peers(peers: List[Peer]) -> List[Peer]:
    """
    Takes a list of Peer objects and pings them all concurrently.
    """
    log.debug(f"--- Pinging {len(peers)} peers in parallel ---")
    # Create a list of tasks, one for each peer if it have open ports
    tasks = [_ping(peer) for peer in peers if peer.is_alive == True]
    # Run all tasks concurrently and wait for them all to complete
    updated_peers = await asyncio.gather(*tasks)
    log.debug("--- All pings complete ---")
    return updated_peers

def _test_hidden_service(proxy: str, addr: str, network: str, port: int, timeout: int = 30) -> Tuple[bool, str]:
    """
    Tests a plain TCP connection to a Tor or i2p hidden service.

    Args:
        proxy: 'addr:port' of proxy used to connect to hidden service
        addr: The overlay network address of the hidden service (without '.onion' or '.b32.i2p').
        network: '.onion' or '.b32.i2p' or other hidden domain
        port: The port number to connect to on the hidden service.
        timeout: The connection timeout in seconds. Tor connections can be slow.

    Returns:
        bool type as the connection success, message for logging
    """
    # Tor's SOCKS5 proxy usually runs on localhost port 9050
    proxy_host = proxy.split(':')[0]
    proxy_port = int(proxy.split(':')[1])
    
    full_address = addr + '.' + network
    
    log.debug(f"Attempting to connect to {full_address}:{port} via socks proxy at {proxy}...")
    
    try:
        # Configure the socket to use the Tor SOCKS5 proxy
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        s.settimeout(timeout)
        
        # Attempt to connect to the onion service
        # The DNS resolution is handled by the Tor proxy
        s.connect((full_address, int(port)))
        #s.connect(('google.com', 80))
        return True, (f"✅ Success! Connection to {full_address}:{port} was successful.")

    except socks.ProxyConnectionError as e:
        return False, (f"🚫 Proxy Error: Could not connect to the Tor or i2p proxy at {proxy}. Is Tor or i2p  running?\n   Details: {e}")
    except socks.GeneralProxyError as e:
        # This often indicates the onion service is offline or unreachable
        return False, (f"❌ Failure: Could not reach the hidden service {full_address}.\n   Details: {e}")
    except socket.timeout:
        return False, (f"❌ Timeout: Connection to {full_address} timed out after {timeout} seconds.")
    except Exception as e:
        return False, (f"An unexpected error occurred: {e}")
    finally:
        # Ensure the socket is always closed
        if 's' in locals():
            s.close()

async def _test_endpoints(endpoints: List[Peer], timeout: int = 5) -> List[Peer]:
    """
    Parses and tests a list of endpoints in the format 'proto:ip:port'.

    Args:
        endpoints: A list of strings, e.g., ["tcp:google.com:80", "wss:echo.websocket.events:443"].
        timeout: The connection timeout in seconds for each test.

    Returns:
        A list of tuples, where each tuple contains the original endpoint string,
        a boolean indicating success, and a status message.
    """
    results = []
    ping_cache = {}
    latency = -2
    loop = asyncio.get_running_loop()
    import time
    curr = 1
    total = len(endpoints)
    
    for peer in endpoints:
        print(f"\rtesting {curr}/{total}...", end='')
        curr += 1
        start_time = time.perf_counter()
        try:
            proto, host, port = peer.proto, peer.addr, peer.port
            if host[0] == '[': # unpack ipv6
                host = host[1:-1]
        except ValueError:
            log.debug(peer.get_uri(), False, "Invalid format. Expected 'proto:ip:port'.")
            continue
        
#         TODO filter peer list
#        if 'internet' == peer.network: continue
        
        if peer.network in ['onion', 'b32.i2p']:
            success, message = _test_hidden_service(peer.proxy, host, peer.network, port)
            log.debug(message)
        elif proto == "tcp":
            success, message = await loop.run_in_executor(
                None, _test_tcp_sync, host, port, timeout
            )
        elif proto == "tls":
            success, message = await loop.run_in_executor(
                None, _test_tls_sync, host, port, timeout
            )
        elif proto in ["ws", "wss"]:
            uri = peer.get_uri()
            success, message = await _test_websocket_async(uri, timeout)
        elif proto == "quic":
            success, message = await _test_quic_async(host, port, timeout)
        else:
            success, message = False, f"Unsupported protocol: '{proto}'."
        
        if success: # results are only if some protocol works
            end_time = time.perf_counter()
            peer.is_alive = True
            peer.latency = int((end_time - start_time) * 1000)
            log.debug(f"latency: {peer.latency} ms")
            assert peer != None, "peer is none"
            results.append(peer)
        log.debug(f"[{'✅ SUCCESS' if success else '❌ FAILURE'}] {message}")
    
    #ping from results only if peer is alive
    print()
    print("testing ping...", end='')
    results = await ping_peers(results)
    print()
    return results

async def main(options: str):
    targets_to_test = get_peers()

    log.debug(f"--- Starting Connection Tests (Timeout={5}s) ---\n")
    results = await _test_endpoints(endpoints=targets_to_test, timeout=5)
    log.debug("\n--- All Tests Complete ---")
    
    results = sorted(results, key=lambda peer: getattr(peer, "ping_latency"))
    
    if options == 'key':
        for peer in results:
            print('# ping_latency:', peer.ping_latency, 
                    '|region:', peer.region, 
                    '|country:', peer.country, 
                    '|proto_latency:', peer.latency
            )
            print(peer)
            print()
    else:
        print_rows = []
        for peer in results:
            assert peer != None, "peer is none from ping"
            print_rows.append(peer.get_row())
        print(tabulate(print_rows, headers=['URI', 'Region', 'Country', 'Proto_latency', 'Ping_latency'], tablefmt="orgtbl"))
    return results



