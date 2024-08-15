# tls-client-and-server
tls-client-and-server

## タイムライン

クライアント実装完了
↓
サーバー実装完了
↓
cryptographyの移植開始
↓
cffiの移植開始
↓
opensslの移植開始
↓
opensslのimport成功(現在)

## すっ飛ばしたthings

### クライアントとサーバー共通

0-RTTに関する実装はすべてしていない(NewSessionTicketなど)
暗号プロトコルの実装に重点を置いたため、実際の暗号計算は外部ライブラリを利用

### クライアント

ssl証明書の検証
- CertificateVerifyに必要なpublic keyなどは回収しているが、証明書が偽造でないかは検証していない(ちゃんとした認証局から発行されているか検証していない)
エラー応答の実装が不十分


### サーバー

同時に接続できるのはひとつのクライアントのみ
エラー応答の実装が不十分

## 追加学習 - 電子辞書で動かしたい！

電子辞書「Brain」には、組み込み用OSである「Windows CE 6.0」(以下、WinCE)が搭載されている

昨年の春から、また昨年12月頃からはコミュニティ内で、WinCEへPython 3.10の移植を行っていた

今回は
- 追加ライブラリの移植
- 未移植の標準ライブラリの拡充
- 暗号ライブラリの移植
を行い、実装したTLSのプログラムを電子辞書で動かすことを目標とした

### python 3.10
https://github.com/brain-hackers/cpython-wince/tree/raspython3

### cryptography
https://github.com/RasPython3/cryptography

### openssl
https://github.com/RasPython3/openssl

### cffi
https://github.com/RasPython3/cffi-wince

