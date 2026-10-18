"""Tests for PCAP parsing and multi-protocol network audit extraction."""
import os
import struct
import tempfile
import unittest

from locaudit import pcap


class PcapTest(unittest.TestCase):
    def test_extract_snis_from_synthetic_pcap(self):
        sni_bytes = b"example.com"
        sni_ext = (
            struct.pack(">HH", 0, len(sni_bytes) + 5)
            + struct.pack(">HBH", len(sni_bytes) + 3, 0, len(sni_bytes))
            + sni_bytes
        )

        ch_body = (
            b"\x03\x03"
            + b"\x00" * 32
            + b"\x00"
            + struct.pack(">H", 2) + b"\xc0\x2f"
            + b"\x01\x00"
            + struct.pack(">H", len(sni_ext))
            + sni_ext
        )

        handshake = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
        tls_record = struct.pack(">BHH", 0x16, 0x0301, len(handshake)) + handshake

        tcp_hdr = struct.pack(">HHIIBBHHH", 12345, 443, 1, 1, (5 << 4), 0x18, 65535, 0, 0)
        ip_hdr = struct.pack(">BBHHHBBHII", 0x45, 0, 20 + len(tcp_hdr) + len(tls_record), 1, 0, 64, 6, 0, 0x0A000001, 0x0A000002)

        packet = ip_hdr + tcp_hdr + tls_record

        pcap_global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)  # LinkType 101 RAW IP
        pkt_hdr = struct.pack("<IIII", 1000, 0, len(packet), len(packet))

        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            f.write(pcap_global_hdr + pkt_hdr + packet)
            f.flush()

            snis = pcap.extract_snis(f.name)
            self.assertEqual(snis, ["example.com"])
            parsed = pcap.parse_pcap(f.name)
            self.assertIn("TLS", parsed["protocols"])
            self.assertEqual(parsed["snis"], ["example.com"])

    def test_missing_or_empty_pcap(self):
        res = pcap.parse_pcap("/nonexistent/file.pcap")
        self.assertEqual(res["snis"], [])
        self.assertEqual(res["dns"], [])
        self.assertEqual(res["protocols"], [])

    def test_real_capture_if_present(self):
        pcap_path = "data/cache/com.agilexrobotics/traffic.pcap"
        if not os.path.isfile(pcap_path):
            self.skipTest(f"{pcap_path} not found")

        result = pcap.parse_pcap(pcap_path)
        self.assertIn("TLS", result["protocols"])
        self.assertIn("DNS", result["protocols"])
        self.assertIn("CoAP", result["protocols"])
        self.assertIn("ICMP", result["protocols"])
        self.assertIn("QUIC", result["protocols"])

        # Check SNIs
        self.assertIn("domestic.mammotion.com", result["snis"])
        self.assertIn("events.mapbox.com", result["snis"])

        # Check ICMP Ping
        self.assertIn("103.235.47.188", result["icmp_targets"])

        # Check CoAP broadcast
        self.assertTrue(any("core.service.dev" in b["payload"] for b in result["broadcasts"]))

        # Check DNS CNAME chaining
        self.assertIn("domestic.mammotion.com", result["dns_resolutions"])
        self.assertTrue(len(result["dns_resolutions"]["domestic.mammotion.com"]["cnames"]) > 0)


if __name__ == "__main__":
    unittest.main()
