#!/bin/bash
# 鍵生成
/bin/mkdir temp
openssl req -x509 -nodes -days 36500 -newkey ec:<(openssl ecparam -name prime256v1) -keyout temp/key.pem -out temp/cert.pem -subj "/C=JP/O=RasPython3 Org./CN=raspython3.org"

# サーバー起動
openssl s_server -accept 50000 -cert temp/cert.pem -key temp/key.pem -CAfile temp/cert.pem -cipher AES128-GCM-SHA256 -serverpref -state -debug -status_verbose -named_curve x25519 -sigalgs ecdsa_secp256r1_sha256 -trace -security_debug_verbose -msg -keylogfile /dev/stdout -www