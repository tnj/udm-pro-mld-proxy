# mld_proxy.py

Solicited-Node マルチキャストアドレス用の軽量な MLD proxy。

## 背景

IPv6 ルーターで WAN の /64 prefix を LAN に配布し、ndppd で NDP proxy を行う構成において、WAN Gateway が MLD Snooping を行っている場合、LAN hosts の Solicited-Node マルチキャストアドレスに対する MLD Report が WAN 側に送信されないため、Gateway が NS を転送せず、一定時間後に Neighbor Discovery が失敗する問題がある。

本スクリプトは、LAN 側の NDP トラフィック (NS/NA) を監視し、LAN hosts の IPv6 アドレスに対応する Solicited-Node マルチキャストグループに WAN 側で参加することで、この問題を解決する。

## ネットワーク構成

```
[WAN Gateway]  MLD Snooping 有効
      |
   [eth9]      WAN (upstream)
      |
  [Linux Router]  ndppd で NDP proxy
      |
    [br0]       LAN (downstream)
      |
 [LAN hosts]   SLAAC でアドレス取得
```

## 動作原理

1. br0 上の NS (DAD を含む) と NA を raw socket で監視
2. LAN hosts の IPv6 アドレスから Solicited-Node マルチキャストアドレス (`ff02::1:ffXX:XXXX`) を算出
3. eth9 でそのマルチキャストグループにカーネルレベルで参加 (`IPV6_JOIN_GROUP`)
4. eth9 から MLDv2 Report を送信し、WAN Gateway に通知
5. 60 秒ごとに全グループの MLD Report を再送信

これにより、WAN Gateway は eth9 を該当グループのメンバーとして認識し、NS を eth9 に転送する。ndppd がその NS を受信して NA を返すことで、LAN hosts の Neighbor Discovery が正常に機能する。

## 前提条件

- Python 3.6 以上
- root 権限
- ndppd が動作していること
- `CONFIG_IPV6_MROUTE` は不要

## 使い方

```
sudo python3 mld_proxy.py <upstream_if> <downstream_if>
```

### 例

```
sudo python3 mld_proxy.py eth9 br0
```

### 出力例

```
MLD Proxy: br0 -> eth9
Listening for NDP on downstream...
Sent MLD Join: ff02::1:ff12:3456 on eth9
Sent MLD Join: ff02::1:ff78:9abc on eth9
Sent MLD Report: ff02::1:ff12:3456 on eth9
Sent MLD Report: ff02::1:ff78:9abc on eth9
```

## systemd でのデーモン化

```ini
# /etc/systemd/system/mld-proxy.service
[Unit]
Description=MLD Proxy for Solicited-Node Multicast
After=network.target ndppd.service

[Service]
ExecStart=/usr/bin/python3 /path/to/mld_proxy.py eth9 br0
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl enable --now mld-proxy.service
```

## タイマー

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| `ADDR_TIMEOUT` | 300 秒 | NDP トラフィックが観測されないアドレスを期限切れとする時間 |
| `REFRESH_INTERVAL` | 60 秒 | 全グループの MLD Report を再送信する間隔 |
| `EXPIRY_CHECK_INTERVAL` | 30 秒 | 期限切れチェックの実行間隔 |

## 制限事項

- link-local アドレス (`fe80::/10`) は対象外（Solicited-Node の proxy は不要なため）
- MLD Report に Router Alert オプションを付加していない。一般的な MLD Snooping 実装では問題ないが、厳密な RFC 準拠が求められる環境では注意が必要
