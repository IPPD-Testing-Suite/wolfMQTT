/* packet_decode_fuzz.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* libFuzzer harness targeting MQTT packet decoding functions directly.
 *
 * Routes the fuzz input to multiple decoder entry points based on the
 * first byte's packet-type nibble (bits 7-4), matching real MQTT dispatch.
 * This exercises MqttDecode_Publish, MqttDecode_Subscribe, the VBI decoder,
 * MqttDecode_String, and MQTT v5 property parsing without requiring a full
 * broker or network stack.
 *
 * Build:
 *   ./configure --enable-broker --enable-v5 --enable-fuzz --disable-tls
 *   make CC=clang \
 *     CFLAGS="-fsanitize=fuzzer-no-link,address -g" \
 *     LDFLAGS="-fsanitize=fuzzer,address"
 *   clang -fsanitize=fuzzer,address -g \
 *     -I. tests/fuzz/packet_decode_fuzz.c src/mqtt_packet.c \
 *     -o packet_decode_fuzz
 *
 * Run:
 *   ./packet_decode_fuzz tests/fuzz/vuln_seeds/ -dict=tests/fuzz/mqtt.dict \
 *     -max_len=4096 -timeout=10
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfmqtt/mqtt_types.h>
#include <wolfmqtt/mqtt_packet.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* libFuzzer entry point prototypes */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Working buffers — sized for max fuzzer input */
#define FUZZ_BUF_SIZE  4096

static MqttPublish   g_publish;
static MqttSubscribe g_subscribe;
static MqttTopic     g_topics[MAX_MQTT_TOPICS];

/* Decode the variable-byte-integer at the start of the input directly. */
static void fuzz_vbi(const uint8_t *data, size_t size)
{
    word32 value = 0;
    MqttDecode_Vbi((byte *)data, &value, (word32)size);
}

/* Route to MqttDecode_Publish. */
static void fuzz_publish(const uint8_t *data, size_t size)
{
    XMEMSET(&g_publish, 0, sizeof(g_publish));
#ifdef WOLFMQTT_V5
    /* Try both protocol levels so v5 property paths are covered. */
    g_publish.protocol_level = (data[0] & 0x01) ?
        MQTT_CONNECT_PROTOCOL_LEVEL_5 : MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif
    MqttDecode_Publish((byte *)data, (int)size, &g_publish);
}

/* Route to MqttDecode_Subscribe (broker-side path). */
static void fuzz_subscribe(const uint8_t *data, size_t size)
{
#ifdef WOLFMQTT_BROKER
    XMEMSET(&g_subscribe, 0, sizeof(g_subscribe));
    XMEMSET(g_topics, 0, sizeof(g_topics));
    g_subscribe.topics = g_topics;
#ifdef WOLFMQTT_V5
    g_subscribe.protocol_level = (data[0] & 0x01) ?
        MQTT_CONNECT_PROTOCOL_LEVEL_5 : MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif
    MqttDecode_Subscribe((byte *)data, (int)size, &g_subscribe);
#else
    (void)data;
    (void)size;
#endif
}

/* Route to MqttDecode_String directly for focused string-bounds testing. */
static void fuzz_string(const uint8_t *data, size_t size)
{
    const char *str = NULL;
    word16 str_len = 0;
    MqttDecode_String((byte *)data, &str, &str_len, (word32)size);
    /* Touch the reported length to catch ASan over-reads */
    if (str != NULL && str_len > 0) {
        volatile byte sink = ((const byte *)str)[str_len - 1];
        (void)sink;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    byte pkt_type;

    if (size < 2) {
        return 0;
    }

    /* Always exercise raw VBI decode regardless of type */
    fuzz_vbi(data + 1, size - 1);

    /* Dispatch on packet type nibble */
    pkt_type = (data[0] >> 4) & 0x0F;
    switch (pkt_type) {
        case MQTT_PACKET_TYPE_PUBLISH:
            fuzz_publish(data, size);
            break;

        case MQTT_PACKET_TYPE_SUBSCRIBE:
            fuzz_subscribe(data, size);
            break;

        default:
            /* For all other types, exercise MqttDecode_String on the
             * remainder so the string-bounds path is always reachable. */
            fuzz_string(data, size);
            break;
    }

    return 0;
}
