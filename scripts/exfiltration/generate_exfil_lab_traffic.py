"""
Controlled Lab Traffic Generator for Exfiltration Detector Validation (PS-26145 — Track B).

Generates two controlled synthetic PCAP experiments:
  1. Asymmetric Outbound Transfer:
     Internal host (192.168.56.102) uploads ~500 KB to external host (203.0.113.195)
     over TCP with minimal response ACKs (orig_bytes=500000, resp_bytes=500, ratio=1000:1).
  2. Inbound-Heavy Download (Negative Control):
     Internal host (192.168.56.102) downloads ~1.5 MB from external host (198.51.100.80)
     over TCP with minimal outbound requests (orig_bytes=1200, resp_bytes=1500000, ratio=0.0008:1).

PCAPs are stored under artifacts/exfiltration/ to preserve data/raw/ untouched.
Runs Zeek 9.0.0 via Docker container to produce conn.log JSON logs.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate_exfil_lab_traffic")

repo_root = Path(__file__).resolve().parent.parent.parent


def generate_asymmetric_upload_pcap(out_path: Path) -> None:
    """Simulate internal host exfiltrating ~500KB to external target."""
    logger.info("Generating asymmetric upload PCAP: %s", out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    src_ip = "192.168.56.102"
    dst_ip = "203.0.113.195"
    src_port = 49200
    dst_port = 8443

    packets = []
    base_ts = 1789800000.0

    # 1. 3-way Handshake
    syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
    syn.time = base_ts
    packets.append(syn)

    syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=5000, ack=1001)
    syn_ack.time = base_ts + 0.01
    packets.append(syn_ack)

    ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=5001)
    ack.time = base_ts + 0.02
    packets.append(ack)

    # 2. Outbound upload: 500 segments of 1,000 bytes payload = 500,000 bytes
    payload_chunk = b"X" * 1000
    client_seq = 1001
    server_ack = 5001

    for i in range(500):
        t = base_ts + 0.05 + (i * 0.02)
        data_pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port, dport=dst_port, flags="PA", seq=client_seq, ack=server_ack
        ) / Raw(load=payload_chunk)
        data_pkt.time = t
        packets.append(data_pkt)
        client_seq += len(payload_chunk)

        # Periodic small ACK from server every 10 packets
        if (i + 1) % 10 == 0:
            srv_ack = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port, dport=src_port, flags="A", seq=server_ack, ack=client_seq
            )
            srv_ack.time = t + 0.005
            packets.append(srv_ack)

    # 3. Connection Teardown
    fin_client = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=client_seq, ack=server_ack)
    fin_client.time = base_ts + 11.0
    packets.append(fin_client)

    fin_server = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=server_ack, ack=client_seq + 1)
    fin_server.time = base_ts + 11.01
    packets.append(fin_server)

    ack_final = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=client_seq + 1, ack=server_ack + 1)
    ack_final.time = base_ts + 11.02
    packets.append(ack_final)

    wrpcap(str(out_path), packets)
    logger.info("Saved %d packets to %s", len(packets), out_path)


def generate_inbound_download_pcap(out_path: Path) -> None:
    """Simulate internal host downloading ~1.5MB from external server (negative test)."""
    logger.info("Generating inbound download PCAP: %s", out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    src_ip = "192.168.56.102"
    dst_ip = "198.51.100.80"
    src_port = 49202
    dst_port = 80

    packets = []
    base_ts = 1789801000.0

    # 1. 3-way Handshake
    syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=2000)
    syn.time = base_ts
    packets.append(syn)

    syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=8000, ack=2001)
    syn_ack.time = base_ts + 0.01
    packets.append(syn_ack)

    ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=2001, ack=8001)
    ack.time = base_ts + 0.02
    packets.append(ack)

    # 2. Client sends small HTTP GET request (1,200 bytes)
    http_req = b"GET /large-update-package.iso HTTP/1.1\r\nHost: cdn.download.example\r\nUser-Agent: LabClient/1.0\r\n" + (b"X-Pad: " + b"A" * 1050 + b"\r\n\r\n")
    req_pkt = IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port, dport=dst_port, flags="PA", seq=2001, ack=8001
    ) / Raw(load=http_req)
    req_pkt.time = base_ts + 0.03
    packets.append(req_pkt)
    client_seq = 2001 + len(http_req)
    server_seq = 8001

    # 3. Server responds with ~1,500 segments of 1,000 bytes = 1,500,000 bytes
    payload_chunk = b"D" * 1000
    for i in range(1500):
        t = base_ts + 0.05 + (i * 0.01)
        resp_pkt = IP(src=dst_ip, dst=src_ip) / TCP(
            sport=dst_port, dport=src_port, flags="PA", seq=server_seq, ack=client_seq
        ) / Raw(load=payload_chunk)
        resp_pkt.time = t
        packets.append(resp_pkt)
        server_seq += len(payload_chunk)

        # Client sends pure ACK every 20 packets
        if (i + 1) % 20 == 0:
            cl_ack = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=src_port, dport=dst_port, flags="A", seq=client_seq, ack=server_seq
            )
            cl_ack.time = t + 0.002
            packets.append(cl_ack)

    # 4. Teardown
    fin_server = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=server_seq, ack=client_seq)
    fin_server.time = base_ts + 16.0
    packets.append(fin_server)

    fin_client = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=client_seq, ack=server_seq + 1)
    fin_client.time = base_ts + 16.01
    packets.append(fin_client)

    ack_final = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="A", seq=server_seq + 1, ack=client_seq + 1)
    ack_final.time = base_ts + 16.02
    packets.append(ack_final)

    wrpcap(str(out_path), packets)
    logger.info("Saved %d packets to %s", len(packets), out_path)


def run_zeek(pcap_path: Path, out_dir: Path) -> None:
    """Run Zeek container to produce JSON conn.log."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rel_pcap = pcap_path.resolve().relative_to(repo_root)
    rel_out = out_dir.resolve().relative_to(repo_root)

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{repo_root}:/work",
        "-w",
        f"/work/{rel_out}",
        "zeek/zeek:lts",
        "zeek",
        "-C",
        "-r",
        f"/work/{rel_pcap}",
        "LogAscii::use_json=T",
    ]
    logger.info("Running Zeek on %s -> %s", rel_pcap, rel_out)
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        logger.error("Zeek failed: %s\n%s", res.stdout, res.stderr)
        raise RuntimeError(f"Zeek execution failed: {res.returncode}")

    conn_log = out_dir / "conn.log"
    if not conn_log.exists():
        raise FileNotFoundError(f"conn.log not generated in {out_dir}")
    logger.info("Zeek logs generated successfully in %s", out_dir)


def main() -> None:
    upload_pcap = repo_root / "artifacts" / "exfiltration" / "asymmetric_upload" / "exfil_upload.pcap"
    download_pcap = repo_root / "artifacts" / "exfiltration" / "inbound_download" / "inbound_download.pcap"

    generate_asymmetric_upload_pcap(upload_pcap)
    generate_inbound_download_pcap(download_pcap)

    run_zeek(upload_pcap, upload_pcap.parent / "zeek")
    run_zeek(download_pcap, download_pcap.parent / "zeek")


if __name__ == "__main__":
    main()
