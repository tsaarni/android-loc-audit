"""Parse packet capture files (PCAP) to extract TLS SNIs, DNS queries, and network findings.

Uses dpkt for robust protocol parsing across Ethernet (LinkType 1) and RAW IP
(LinkType 12 / 101, used by Android VPN captures).
"""
import os
import socket
from collections import defaultdict
import dpkt


def _is_local_or_ephemeral(port):
    """Check if port is likely an ephemeral client port (> 1024 and not standard service)."""
    standard_services = {1883, 3083, 5683, 8080, 8443, 8883, 9000, 9090}
    return port > 1024 and port not in standard_services


def parse_pcap(pcap_path):
    """Parse a PCAP file and extract multi-protocol privacy & infrastructure findings.

    Returns a dict with:
        - snis: list of unique TLS ClientHello SNI hostnames
        - dns: list of unique DNS query hostnames
        - dns_resolutions: dict mapping queried domain to {'cnames': [...], 'ips': [...]}
        - broadcasts: list of unencrypted local LAN discovery/broadcast messages
        - icmp_targets: list of remote IPs pinged via ICMP echo requests
        - protocols: sorted list of active application/transport protocols
        - endpoints: list of remote service endpoints with traffic volume & mapped domains
    """
    snis = []
    dns_queries = []
    dns_cnames = {}
    dns_ips = defaultdict(list)
    broadcasts = []
    seen_broadcast_payloads = set()
    icmp_targets = []
    remote_services = defaultdict(lambda: {"packets": 0, "bytes": 0})
    protocols = set()

    if not os.path.isfile(pcap_path):
        return {
            "snis": [],
            "dns": [],
            "dns_resolutions": {},
            "broadcasts": [],
            "icmp_targets": [],
            "protocols": [],
            "endpoints": [],
        }

    try:
        with open(pcap_path, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            datalink = reader.datalink()

            for ts, buf in reader:
                try:
                    if datalink in (101, 12):  # RAW IP / DLT_RAW
                        ver = buf[0] >> 4
                        if ver == 4:
                            ip = dpkt.ip.IP(buf)
                        elif ver == 6:
                            ip = dpkt.ip6.IP6(buf)
                        else:
                            continue
                    elif datalink == 1:  # Ethernet
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                            ip = eth.data
                        else:
                            continue
                    else:
                        continue

                    if isinstance(ip, dpkt.ip.IP):
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                    else:
                        src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                        dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)

                    # ICMP / Ping Target Detection
                    if isinstance(ip.data, dpkt.icmp.ICMP):
                        protocols.add("ICMP")
                        if ip.data.type == 8:  # Echo Request
                            if dst_ip not in icmp_targets:
                                icmp_targets.append(dst_ip)

                    # UDP Handling
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        sport, dport = udp.sport, udp.dport
                        data = udp.data

                        # Map remote server vs local client
                        if src_ip.startswith("10.215.") or _is_local_or_ephemeral(sport):
                            rem_ip, rem_port = dst_ip, dport
                        else:
                            rem_ip, rem_port = src_ip, sport

                        remote_services[(rem_ip, rem_port, "UDP")]["packets"] += 1
                        remote_services[(rem_ip, rem_port, "UDP")]["bytes"] += len(buf)

                        # DNS
                        if dport == 53 or sport == 53:
                            protocols.add("DNS")
                            try:
                                dns = dpkt.dns.DNS(data)
                                for q in dns.qd:
                                    if q.name and q.name not in dns_queries:
                                        dns_queries.append(q.name)
                                for ans in dns.an:
                                    if ans.type == dpkt.dns.DNS_CNAME:
                                        dns_cnames[ans.name] = ans.cname
                                    elif ans.type == dpkt.dns.DNS_A:
                                        ip_str = socket.inet_ntoa(ans.ip)
                                        if ip_str not in dns_ips[ans.name]:
                                            dns_ips[ans.name].append(ip_str)
                            except Exception:
                                pass

                        # CoAP / IoT Local Discovery (Port 5683)
                        elif dport == 5683 or sport == 5683:
                            protocols.add("CoAP")
                            if b"\xff" in data:
                                body = data.split(b"\xff", 1)[1]
                                try:
                                    text = body.decode("utf-8", errors="ignore")
                                    if text and text not in seen_broadcast_payloads:
                                        seen_broadcast_payloads.add(text)
                                        broadcasts.append({
                                            "proto": "CoAP",
                                            "port": dport,
                                            "dst": dst_ip,
                                            "payload": text,
                                        })
                                except Exception:
                                    pass

                        # QUIC / HTTP/3 (UDP 443 with RFC 9000 fixed bit set)
                        elif (dport == 443 or sport == 443) and len(data) > 0 and (data[0] & 0x40):
                            protocols.add("QUIC")

                    # TCP Handling
                    elif isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        sport, dport = tcp.sport, tcp.dport
                        data = tcp.data

                        # Map remote server vs local client
                        if src_ip.startswith("10.215.") or _is_local_or_ephemeral(sport):
                            rem_ip, rem_port = dst_ip, dport
                        else:
                            rem_ip, rem_port = src_ip, sport

                        remote_services[(rem_ip, rem_port, "TCP")]["packets"] += 1
                        remote_services[(rem_ip, rem_port, "TCP")]["bytes"] += len(buf)

                        # TLS ClientHello (0x16 Handshake)
                        if len(data) > 0 and data[0] == 0x16:
                            protocols.add("TLS")
                            try:
                                tls = dpkt.ssl.TLSRecord(data)
                                hs = dpkt.ssl.TLSHandshake(tls.data)
                                if isinstance(hs.data, dpkt.ssl.TLSClientHello):
                                    ch = hs.data
                                    for ext_type, ext_data in ch.extensions:
                                        # ext_type 0 is server_name (SNI)
                                        if ext_type == 0 and len(ext_data) >= 5:
                                            name_len = int.from_bytes(ext_data[3:5], "big")
                                            host = ext_data[5:5 + name_len].decode("ascii", errors="ignore")
                                            if host and host not in snis:
                                                snis.append(host)
                            except Exception:
                                pass
                except Exception:
                    continue
    except (OSError, ValueError):
        pass

    # Resolve CNAME chains to final IP addresses
    dns_resolutions = {}
    ip_to_domains = defaultdict(set)
    for q in dns_queries:
        curr = q
        cnames = []
        visited = {curr}
        while curr in dns_cnames:
            nxt = dns_cnames[curr]
            if nxt in visited:
                break
            visited.add(nxt)
            cnames.append(nxt)
            curr = nxt
        ips = sorted(dns_ips.get(curr, []))
        dns_resolutions[q] = {"cnames": cnames, "ips": ips}
        for ip_addr in ips:
            ip_to_domains[ip_addr].add(q)

    # Format remote endpoints sorted by traffic volume
    endpoints = []
    for (rem_ip, rem_port, proto), stats in sorted(
        remote_services.items(), key=lambda x: -x[1]["packets"]
    ):
        matched_domains = sorted(ip_to_domains.get(rem_ip, []))
        endpoints.append({
            "ip": rem_ip,
            "port": rem_port,
            "proto": proto,
            "packets": stats["packets"],
            "bytes": stats["bytes"],
            "domains": matched_domains,
        })

    return {
        "snis": snis,
        "dns": dns_queries,
        "dns_resolutions": dns_resolutions,
        "broadcasts": broadcasts,
        "icmp_targets": icmp_targets,
        "protocols": sorted(protocols),
        "endpoints": endpoints,
    }


def extract_snis(pcap_path):
    """Extract unique TLS ClientHello SNI hostnames from a PCAP file."""
    return parse_pcap(pcap_path)["snis"]


def extract_dns(pcap_path):
    """Extract unique DNS query names from a PCAP file."""
    return parse_pcap(pcap_path)["dns"]
