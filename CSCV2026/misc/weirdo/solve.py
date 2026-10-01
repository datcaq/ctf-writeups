"""CSCV2026 / Misc / Weirdo: reconstruct the GPS text (read visually).

Supports the challenge's little-endian Ethernet/IPv4/UDP PCAP format.
"""

import argparse
from pathlib import Path
import struct

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.collections import LineCollection
import numpy as np


def mavlink_packets(path):
    raw = path.read_bytes()
    if len(raw) < 24 or raw[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("Expected a little-endian microsecond PCAP")
    if struct.unpack_from("<I", raw, 20)[0] != 1:
        raise ValueError("Expected Ethernet link type")
    offset = 24
    while offset < len(raw):
        _, _, size, _ = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        packet = raw[offset:offset + size]
        offset += size
        if len(packet) < 42 or packet[12:14] != b"\x08\x00":
            continue
        if packet[23] != 17:
            continue
        udp = 14 + (packet[14] & 15) * 4
        if len(packet) < udp + 8:
            continue
        length = struct.unpack_from("!H", packet, udp + 4)[0]
        message = packet[udp + 8:udp + length]
        if len(message) >= 12 and message[0] == 0xFD:
            if len(message) >= message[1] + 12:
                yield message


def crc_x25(data):
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def extract_positions(path):
    points = []
    for message in mavlink_packets(path):
        sysid = message[5]
        msgid = int.from_bytes(message[7:10], "little")
        if sysid != 3 or msgid != 33:
            continue
        end = 10 + message[1]
        stored_crc = int.from_bytes(message[end:end + 2], "little")
        # GLOBAL_POSITION_INT has CRC_EXTRA=104. Exclude the magic byte.
        if crc_x25(message[1:end] + bytes([104])) != stored_crc:
            continue
        payload = message[10:end].ljust(28, b"\0")
        _, lat, lon, _ = struct.unpack_from("<Iiii", payload)
        points.append((lon / 1e7, lat / 1e7))
    if len(points) < 2:
        raise ValueError("Not enough CRC-valid positions from sysid 3")
    return np.array(points)


def render(points, output):
    xy = points - points.mean(axis=0)
    xy[:, 0] *= np.cos(np.deg2rad(10.77))
    _, _, axes = np.linalg.svd(xy, full_matrices=False)
    rotated = xy @ axes.T
    # PCA axes have arbitrary signs: preserve handedness and eastward reading.
    if np.linalg.det(axes) < 0:
        rotated[:, 1] *= -1
    if np.corrcoef(xy[:, 0], rotated[:, 0])[0, 1] < 0:
        rotated *= -1
    segments = np.stack((rotated[:-1], rotated[1:]), axis=1)
    nearby = np.linalg.norm(rotated[1:] - rotated[:-1], axis=1) < 0.0003
    fig, ax = plt.subplots(figsize=(24, 4))
    ax.add_collection(LineCollection(segments[nearby], colors="#183b70", linewidths=0.8))
    ax.scatter(rotated[:, 0], rotated[:, 1], s=3, c="#183b70")
    ax.autoscale()
    ax.set_aspect("equal")
    ax.axis("off")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=160, bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="Path to challenge.pcap")
    parser.add_argument("--output", type=Path, default=Path("gps-flag.png"))
    args = parser.parse_args()
    points = extract_positions(args.pcap)
    render(points, args.output)
    print(f"Rendered {len(points)} CRC-valid positions: {args.output.resolve()}")
    print("Read the lower line of the image and wrap it in CSCV2026{...}.")


if __name__ == "__main__":
    main()
