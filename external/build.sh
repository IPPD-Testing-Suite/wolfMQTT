#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build wolfSSL (dependency of wolfMQTT)
cd $SRC/wolfssl/
autoreconf -ivf
if [[ $CFLAGS = *sanitize=memory* ]]
then
    ./configure --enable-static --disable-crypttests --disable-examples --disable-asm
elif [[ $CFLAGS = *-m32* ]]
then
    ./configure --enable-static --disable-crypttests --disable-examples --disable-fastmath
else
    ./configure --enable-static --disable-crypttests --disable-examples
fi
make -j$(nproc)
export CFLAGS="$CFLAGS -I $(realpath .)"
export LDFLAGS="-L$(realpath src/.libs/)"

# Build wolfMQTT
# --enable-v5      : MQTT v5 property decoding paths (required by packet_decode_fuzz)
# --enable-broker  : broker-side decoders, e.g. MqttDecode_Subscribe (WOLFMQTT_BROKER)
cd $SRC/wolfmqtt/
./autogen.sh
./configure --enable-static --disable-examples --enable-v5 --enable-broker
make -j$(nproc)

# ── In-tree packet-decode harness (targets the 5 injected vulnerabilities) ──────
$CC $CFLAGS \
    -DWOLFMQTT_BROKER \
    -I $SRC/wolfssl/ \
    -I $SRC/wolfmqtt/ \
    $SRC/wolfmqtt/tests/fuzz/packet_decode_fuzz.c \
    $SRC/wolfmqtt/src/.libs/libwolfmqtt.a \
    $SRC/wolfssl/src/.libs/libwolfssl.a \
    $LIB_FUZZING_ENGINE \
    -o $OUT/wolfmqtt-packet-decode-fuzzer

# Bundle the vulnerability seed corpus so OSS-Fuzz uses them as starting inputs
zip -j $OUT/wolfmqtt-packet-decode-fuzzer_seed_corpus.zip \
    $SRC/wolfmqtt/tests/fuzz/vuln_seeds/*.bin
