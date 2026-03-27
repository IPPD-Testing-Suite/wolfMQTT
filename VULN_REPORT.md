# wolfMQTT Vulnerability Report

Five bugs were injected into `src/mqtt_packet.c`. Fuzzing harnesses and
seed corpora are provided for each one.

---

## Fuzzing Infrastructure

| Artifact | Path |
|---|---|
| Harness | `tests/fuzz/packet_decode_fuzz.c` |
| Seed generator | `tests/fuzz/gen_vuln_seeds.py` |
| Seed directory | `tests/fuzz/vuln_seeds/` |

### Build

```sh
./configure --enable-broker --enable-v5 --enable-fuzz --disable-tls
make CC=clang \
  CFLAGS="-fsanitize=fuzzer-no-link,address -g" \
  LDFLAGS="-fsanitize=fuzzer,address"
```

### Run

```sh
python3 tests/fuzz/gen_vuln_seeds.py   # generate seeds
./packet_decode_fuzz tests/fuzz/vuln_seeds/ \
  -dict=tests/fuzz/mqtt.dict -max_len=4096 -timeout=10
```

---

## Vulnerability 1 — VBI Loop Termination Off-by-One

| Field | Value |
|---|---|
| File | `src/mqtt_packet.c` |
| Function | `MqttDecode_Vbi` |
| Change | `if (rc >= 4)` → `if (rc >= 5)` |
| Seed | `tests/fuzz/vuln_seeds/vuln1_vbi_5byte.bin` |

### Description

`MqttDecode_Vbi` decodes the MQTT variable-byte integer (VBI) encoding used
for the remaining-length field of every packet fixed header. The MQTT
specification permits at most four continuation bytes. The original guard
fires at `rc == 4`; after the change it fires at `rc == 5`, allowing a fifth
byte to be consumed.

At the fifth iteration `multiplier` equals `128^4 = 268 435 456` (0x10000000).
Multiplying the masked byte value by this amount and adding to the accumulator
silently wraps the `word32` result, producing an attacker-controlled
`remain_len` that is entirely independent of the bytes that follow. Every
caller that trusts `remain_len` to bound subsequent reads is then
potentially exposed to out-of-bounds memory access.

### Trigger Conditions

A raw MQTT packet whose remaining-length VBI field begins with four bytes each
having the continuation bit (bit 7) set, followed by a non-zero fifth byte.

Seed bytes (hex): `30 80 80 80 80 01 00 01 61 68 65 6c 6c 6f`

---

## Vulnerability 2 — PUBLISH Payload Length Integer Underflow

| Field | Value |
|---|---|
| File | `src/mqtt_packet.c` |
| Function | `MqttDecode_Publish` |
| Change | `if (variable_len > remain_len)` → `if (variable_len < remain_len)` |
| Seed | `tests/fuzz/vuln_seeds/vuln2_publish_payload_underflow.bin` |

### Description

After decoding the PUBLISH variable header (topic name, optional packet ID,
optional properties), the function computes the payload length as:

```c
payload_len = remain_len - variable_len;
```

The original guard prevents execution from reaching this line when
`variable_len > remain_len`. After the change the sense of the comparison is
inverted: the guard now fires (returning an error) for all *valid* packets
where there is payload data (`variable_len < remain_len`), while
*malformed* packets where `variable_len > remain_len` pass through silently.

For such a malformed packet, `payload_len` is a negative `int`. It is
subsequently stored in `publish->buffer_len` and `publish->total_len`, which
are `word32` fields. The negative value wraps to a very large unsigned
integer (e.g., `variable_len - remain_len = 7` yields `buffer_len = 0xFFFFFFF9`),
causing callers to treat an arbitrary amount of memory beyond the receive
buffer as payload data.

### Trigger Conditions

A PUBLISH packet whose fixed-header `remain_len` VBI is smaller than the
number of bytes consumed by the variable header (e.g., a topic-name length
prefix claiming 8 bytes but `remain_len = 3`).

Seed bytes (hex): `30 03 00 08 61 62 63 64 65 66 67 68`

---

## Vulnerability 3 — SUBSCRIBE Topic-Count Out-of-Bounds Write

| Field | Value |
|---|---|
| File | `src/mqtt_packet.c` |
| Function | `MqttDecode_Subscribe` |
| Change | `if (subscribe->topic_count >= MAX_MQTT_TOPICS)` → `if (subscribe->topic_count > MAX_MQTT_TOPICS)` |
| Seed | `tests/fuzz/vuln_seeds/vuln3_subscribe_oob_write.bin` |

### Description

The broker-side SUBSCRIBE decoder iterates over topic filters encoded in the
packet payload. `subscribe->topics` is a caller-supplied array dimensioned
`MAX_MQTT_TOPICS` (12). The original loop guard fires when
`topic_count == MAX_MQTT_TOPICS` (i.e., before writing the 13th slot).
After changing `>=` to `>`, the guard fires only when
`topic_count == MAX_MQTT_TOPICS + 1`, meaning the code writes one element
past the end of the array (`topics[12]`) before detecting the overflow.

An attacker supplying exactly `MAX_MQTT_TOPICS + 1` (13) topic filters in a
single SUBSCRIBE packet will corrupt whichever memory follows the topics array
on the broker's stack or heap, depending on how the caller allocates
`subscribe->topics`.

### Trigger Conditions

A SUBSCRIBE packet with 13 or more topic-filter entries. Each entry is at
minimum 4 bytes (2-byte length prefix + 1-byte name + 1-byte QoS option).
The seed contains exactly 13 minimal topics.

---

## Vulnerability 4 — Binary Property Buffer Over-Read

| Field | Value |
|---|---|
| File | `src/mqtt_packet.c` |
| Function | `MqttDecode_Props` |
| Change | `cur_prop->data_bin.len <= (buf_len - (buf - pbuf))` → `cur_prop->data_bin.len <= (buf_len + (buf - pbuf))` |
| Seed | `tests/fuzz/vuln_seeds/vuln4_binary_prop_overread.bin` |

### Description

`MqttDecode_Props` handles MQTT v5 property decoding. For properties of type
`MQTT_DATA_TYPE_BINARY` (e.g., `CORRELATION_DATA`, property ID 0x09), the
code reads a 2-byte length field and then sets a pointer into the current
position in the receive buffer.

The guard `cur_prop->data_bin.len <= (buf_len - (buf - pbuf))` verifies that
the declared binary length does not exceed the remaining bytes in the buffer.
After the change, the subtraction becomes addition, making
`buf_len + (buf - pbuf)` a value that grows with the current offset rather
than shrinking. For any `data_bin.len` up to approximately `2 * buf_len` the
check passes, allowing `buf` to advance `data_bin.len` bytes past the actual
buffer end. The pointer stored in `cur_prop->data_bin.data` and the
subsequent `buf` increment both reference out-of-bounds memory.

### Trigger Conditions

An MQTT v5 packet containing a binary-type property whose declared length
exceeds the remaining bytes in the receive buffer. The harness signals
protocol level v5 via the LSB of the first byte (`data[0] & 0x01 == 1`).

Seed: PUBLISH (type nibble 3, LSB 1 = `0x31`), remaining length 9, with a
`CORRELATION_DATA` property claiming 65535 bytes but supplying only 2.

---

## Vulnerability 5 — String Length Bounds Check Neutralised

| Field | Value |
|---|---|
| File | `src/mqtt_packet.c` |
| Function | `MqttDecode_String` |
| Change | `(word32)str_len > buf_len - (word32)len` → `(word32)str_len > buf_len + (word32)len` |
| Seed | `tests/fuzz/vuln_seeds/vuln5_string_overread.bin` |

### Description

`MqttDecode_String` reads a 2-byte big-endian length prefix (`len = 2`) then
returns a pointer into the buffer at that offset together with the declared
string length. The guard ensures the declared string fits within the remaining
buffer space:

```c
if ((word32)str_len > buf_len - (word32)len) { /* error */ }
```

After the change, `buf_len - len` becomes `buf_len + len`. Because `str_len`
is a `word16` (maximum 65535) and `buf_len + 2` is almost always larger, the
guard effectively never fires. The returned pointer and `str_len` indicate a
string that extends arbitrarily far beyond the actual receive buffer. Any
caller that reads or copies `str_len` bytes from the returned pointer will
access out-of-bounds memory.

This function is called from every packet decoder (PUBLISH topic, CONNECT
client-ID/username/password, SUBSCRIBE topic filters, MQTT v5 string
properties), so the impact is broad.

### Trigger Conditions

Any MQTT packet containing a string field whose 2-byte length prefix declares
more bytes than are available in the buffer. The default branch of the harness
calls `MqttDecode_String` directly for all non-PUBLISH/non-SUBSCRIBE types.

Seed bytes (hex): `00 02 00 C8 DE AD BE EF`
(string claims 200 bytes; buffer holds only 4 bytes of data)

---

## Summary Table

| # | Function | Root Cause | Impact |
|---|---|---|---|
| 1 | `MqttDecode_Vbi` | Off-by-one loop guard allows 5-byte VBI | `remain_len` integer overflow → OOB read in all callers |
| 2 | `MqttDecode_Publish` | Inverted comparison skips payload length check | Negative `payload_len` wraps to huge `buffer_len` → OOB read |
| 3 | `MqttDecode_Subscribe` | Off-by-one topic-count guard | OOB write to `topics[MAX_MQTT_TOPICS]` |
| 4 | `MqttDecode_Props` | Addition instead of subtraction in binary bounds check | `buf` pointer advances past buffer end → OOB read |
| 5 | `MqttDecode_String` | Addition instead of subtraction neutralises length check | Returned `str` pointer ranges beyond buffer → OOB read |
