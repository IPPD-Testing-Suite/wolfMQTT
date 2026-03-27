#!/usr/bin/env python3
# gen_vuln_seeds.py - Generate seed corpus targeting injected vulnerabilities
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# Creates seed files in tests/fuzz/vuln_seeds/ that drive the packet_decode_fuzz
# harness toward the five injected code paths.
#
# Usage: python3 tests/fuzz/gen_vuln_seeds.py

import os
import struct

SEED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_seeds")


def encode_vbi(length):
    """Encode MQTT remaining length as variable byte integer."""
    encoded = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)


def mqtt_string(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return struct.pack("!H", len(s)) + s


def mqtt_packet(pkt_type, flags, payload):
    header = bytes([(pkt_type << 4) | (flags & 0x0F)])
    return header + encode_vbi(len(payload)) + payload


def write_seed(name, data):
    path = os.path.join(SEED_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  wrote {name} ({len(data)} bytes)")


# ---------------------------------------------------------------------------
# Seed 1: VBI 5-byte overflow (targets Bug 1 — MqttDecode_Vbi rc >= 5 check)
#
# A PUBLISH packet whose remaining-length field is encoded with 5 continuation
# bytes.  The patched code raises the guard from rc>=4 to rc>=5, so the 5th
# byte is consumed.  multiplier at byte 5 is 128^4 = 0x10000000; multiplying
# any non-zero byte value produces a word32 wraparound, corrupting remain_len.
# ---------------------------------------------------------------------------
def seed_vbi_5byte():
    # Fixed header: PUBLISH QoS 0
    pkt_type_byte = bytes([0x30])
    # 5-byte VBI: 0x80 0x80 0x80 0x80 0x01 encodes value
    # = 0*1 + 0*128 + 0*16384 + 0*2097152 + 1*268435456 (overflows word32)
    vbi_5 = bytes([0x80, 0x80, 0x80, 0x80, 0x01])
    # Minimal topic name after the malformed header
    topic = mqtt_string("a")
    payload = b"hello"
    return pkt_type_byte + vbi_5 + topic + payload


# ---------------------------------------------------------------------------
# Seed 2: PUBLISH payload length integer underflow (targets Bug 2)
#
# remain_len is declared small (3) in the fixed header, but the topic-name
# field claims 8 bytes (len prefix 0x00 0x08 + 8-byte name).  After decoding
# the topic, variable_len = 10 > remain_len = 3.
#
# Patched condition `variable_len < remain_len` is FALSE (10 < 3 is false),
# so execution continues.  payload_len = remain_len - variable_len = 3 - 10
# = -7 (int), which wraps to 0xFFFFFFF9 when stored in publish->buffer_len
# (word32), causing a massive apparent buffer length.
# ---------------------------------------------------------------------------
def seed_publish_payload_underflow():
    pkt_type_byte = bytes([0x30])       # PUBLISH, QoS 0
    vbi_remain    = bytes([0x03])       # remain_len = 3 (only 3 bytes follow)
    # Topic name field claims 8-byte string but packet only has 3 remaining bytes
    topic_field   = struct.pack("!H", 8) + b"abcdefgh"
    return pkt_type_byte + vbi_remain + topic_field


# ---------------------------------------------------------------------------
# Seed 3: Subscribe topic-count OOB write (targets Bug 3)
#
# Encodes MAX_MQTT_TOPICS+1 = 13 topics in a single SUBSCRIBE packet.
# The patched guard changes >= to >, so topic_count is allowed to reach 12
# before the check fires, writing topics[12] which is one element past the
# caller-allocated array of MAX_MQTT_TOPICS entries.
# ---------------------------------------------------------------------------
def seed_subscribe_oob():
    MAX_MQTT_TOPICS = 12
    packet_id = struct.pack("!H", 1)
    topics = b""
    for i in range(MAX_MQTT_TOPICS + 1):   # 13 topics
        name = ("t%d" % i).encode()
        topics += mqtt_string(name) + bytes([0x01])   # QoS 1
    payload = packet_id + topics
    return mqtt_packet(8, 0x02, payload)


# ---------------------------------------------------------------------------
# Seed 4: Binary property bounds-check bypass (targets Bug 4)
#
# An MQTT v5 PUBLISH with a CORRELATION_DATA property (type 0x09, binary).
# The patched check is:
#   if (data_bin.len <= (buf_len + (buf - pbuf)))   [bug]
# instead of:
#   if (data_bin.len <= (buf_len - (buf - pbuf)))   [correct]
#
# At the point the check runs the props buffer is 5 bytes and the cursor is
# 3 bytes in (1 VBI + 2 Num), leaving 2 actual bytes.
#   correct : data_bin.len <= 5 - 3 = 2   → rejects len=3
#   buggy   : data_bin.len <= 5 + 3 = 8   → accepts len=3 → buf over-advances
#
# bin_len must be in the window (remaining_bytes, buf_len + offset], i.e. (2,8].
# Using 3 places buf one byte past the 5-byte props buffer end.
# ---------------------------------------------------------------------------
def seed_binary_prop_overread():
    topic   = mqtt_string("x")              # 3 bytes: 0x00 0x01 'x'

    # Properties section (5 bytes total):
    #   0x09            CORRELATION_DATA property id (1 byte VBI)
    #   0x00 0x03       binary length = 3 (claims 3 bytes, only 2 follow)
    #   0xAA 0xBB       actual data (2 bytes — 1 short of claimed 3)
    prop_id   = bytes([0x09])
    bin_len   = struct.pack("!H", 3)
    bin_data  = b"\xAA\xBB"
    props     = prop_id + bin_len + bin_data   # 5 bytes
    props_len = encode_vbi(len(props))         # 0x05 (1 byte)

    var_header    = topic + props_len + props  # 3 + 1 + 5 = 9 bytes
    pkt_type_byte = bytes([0x31])              # PUBLISH, LSB=1 → v5 in harness
    vbi_remain    = encode_vbi(len(var_header))
    return pkt_type_byte + vbi_remain + var_header


# ---------------------------------------------------------------------------
# Seed 5: String bounds-check disabled (targets Bug 5)
#
# fuzz_string() passes the entire input buffer directly to MqttDecode_String,
# so data[0..1] ARE the MQTT string length prefix (not a packet header).
# The patched check is:
#   if ((word32)str_len > buf_len + (word32)len)   [bug, len=2]
# instead of:
#   if ((word32)str_len > buf_len - (word32)len)   [correct]
#
# With a 6-byte buffer and str_len=7:
#   correct : 7 > 6 - 2 = 4  → TRUE  → returns error (safe)
#   buggy   : 7 > 6 + 2 = 8  → FALSE → no error → str[6] accessed OOB
#
# data[0] = 0x00 → pkt_type nibble = 0 (RESERVED), routes to default branch
# which calls fuzz_string(data, 6). data[0..1] = 0x00 0x07 → str_len = 7.
# ---------------------------------------------------------------------------
def seed_string_overread():
    # Entire 6-byte buffer is handed to MqttDecode_String:
    #   bytes 0-1 : str_len = 7  (the MQTT 2-byte length prefix)
    #   bytes 2-5 : 4 bytes of actual string data
    # str_len (7) exceeds actual data (4 bytes) → OOB on str[4], str[5], str[6]
    return bytes([0x00, 0x07, 0xAA, 0xBB, 0xCC, 0xDD])


def main():
    os.makedirs(SEED_DIR, exist_ok=True)
    print(f"Writing seeds to {SEED_DIR}/")

    write_seed("vuln1_vbi_5byte.bin",              seed_vbi_5byte())
    write_seed("vuln2_publish_payload_underflow.bin", seed_publish_payload_underflow())
    write_seed("vuln3_subscribe_oob_write.bin",    seed_subscribe_oob())
    write_seed("vuln4_binary_prop_overread.bin",   seed_binary_prop_overread())
    write_seed("vuln5_string_overread.bin",        seed_string_overread())

    count = len(os.listdir(SEED_DIR))
    print(f"Done — {count} seed files generated.")


if __name__ == "__main__":
    main()
