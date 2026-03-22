# AURORA
Attested Unlinkable Routing with Overlay Relay Assurance.
英語版のREADMEは[こちら](README.md)

AURORA は、ゼロ知識証明を基盤にした、プライバシー保護志向のルーティングおよびミドルボックスです。
暗号化された状態のペイロードが任意のコンテンツに属していないかを復号化せず検証することが可能になります。



## クイックスタート

```sh
cargo build --release
cargo run -p aurora-router
cargo run -p aurora-proxy
```

最小のローカル構成は [docs/localnet-three-router.md](docs/localnet-three-router.md) を参照してください。

## ステータス

実験的な研究コードです。まだ監査は受けていません。

