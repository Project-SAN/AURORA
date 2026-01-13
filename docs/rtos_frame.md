# RTOS/ベアメタル向けの最小フロー例

この例は std I/O を使わず、`router::frame` のエンコード/デコードで
「受信バッファ → 検証・処理 → 送信バッファ」を構成する最小形です。

## 前提
- 受信は「フレーム全体が一度で届く」想定
- `Router` にポリシー/ルートは事前に投入済み

## 擬似コード
```rust
use hornet::router::frame;
use hornet::router::Router;
use hornet::node::{NoReplay, ReplayFilter};
use hornet::forward::Forward;
use hornet::time::TimeProvider;
use hornet::types::{PacketDirection, Result};

struct FixedTime(u32);
impl TimeProvider for FixedTime {
    fn now_coarse(&self) -> u32 {
        self.0
    }
}

struct TxBuffer;
impl Forward for TxBuffer {
    fn send(
        &mut self,
        _rseg: &hornet::types::RoutingSegment,
        _chdr: &hornet::types::Chdr,
        _ahdr: &hornet::types::Ahdr,
        _payload: &mut alloc::vec::Vec<u8>,
        _direction: PacketDirection,
    ) -> Result<()> {
        // 実装側で送信処理に置き換える
        Ok(())
    }
}

fn process_one_frame(router: &Router, sv: hornet::types::Sv, rx: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    let mut decoded = frame::decode_frame(rx)?;

    let time = FixedTime(1_700_000_000);
    let mut forward = TxBuffer;
    let mut replay = NoReplay;

    match decoded.direction {
        PacketDirection::Forward => {
            router.process_forward_packet(
                sv,
                &time,
                &mut forward,
                &mut replay,
                &mut decoded.chdr,
                &mut decoded.ahdr,
                &mut decoded.payload,
            )?;
        }
        PacketDirection::Backward => {
            router.process_backward_packet(
                sv,
                &time,
                &mut forward,
                &mut replay,
                &mut decoded.chdr,
                &mut decoded.ahdr,
                &mut decoded.payload,
            )?;
        }
    }

    Ok(frame::encode_frame(
        decoded.direction,
        &decoded.chdr,
        &decoded.ahdr,
        &decoded.payload,
    ))
}
```
