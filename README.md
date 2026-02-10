# mld_proxy.py

NURO光のSONY NSD-G1000T(S)配下に設置されたUDM-Proにおいて、Single Network設定したIPv6環境で、IPv6通信を維持するスクリプト

## 背景

UDM-Pro で WAN に /64 prefix が RA 配布されているとき、 SLAAC + Single Network の設定を行うことで、 LAN 側に WAN と同一の prefix を使った IPv6 ネットワークを構成できる。このとき内部的には ndppd で NDP proxy が行われており、 WAN Gateway からの NS が LAN 側ホストに到達し、ホストからの NA によって WAN Gateway の NDP キャッシュの有効期限が更新されることが期待されている。

通常、 WAN Gateway からの NS は Solicited-Node マルチキャストアドレスに送出される。仕様上、マルチキャストパケットは端末のすべてのポートに対して送出されるが、このとき WAN Gateway が MLD Snooping を行っていた場合、パケットは Solicited-Node マルチキャストグループに参加しているホストが存在するポートにのみ送出される。

一方 UDM-Pro では、 LAN 側ホストの Solicited-Node マルチキャストグループへの参加や、対応する MLD Report は LAN 内で完結し、 WAN 側には転送されていない。このため、 WAN ネットワークにはマルチキャストグループが存在しないとみなされ、 WAN Gateway は NS を送出することなく、一定時間後に NDP キャッシュが破棄され、通信が行えなくなるという問題がある。

本スクリプトは、LAN 側の NDP トラフィック (NS/NA) を監視し、 WAN 側において LAN 側ホストの IPv6 アドレスに対応する Solicited-Node マルチキャストグループに参加することで、 WAN Gateway から UDM-Pro に対して NS が送出されるようにし、この問題を解決する。

## ネットワーク構成

```
[WAN Gateway]  MLD Snooping 有効 (SONY NSD-G1000TS など)
      |
   [eth9]      WAN (upstream)
      |
  [UDM Pro]    ndppd で NDP proxy
      |
    [br0]      LAN (downstream)
      |
 [LAN hosts]   SLAAC でアドレス取得
```

## UDM-Pro の IPv6 設定

UDM-Pro の管理画面で、Internet (WAN1) の IPv6 Configuration を以下のように設定する:

- **Connection**: SLAAC + Single Network
- **Network**: Default (または使用する Network)

この設定により、UDM-Pro 内蔵の NDP Proxy (ndppd) が有効になり、 NS/NA が WAN と選択した Network の間で転送される。クライアントは SLAAC で WAN 側と同一 prefix のアドレスを取得できる。

### MLD Snooping による問題

NDP Proxy だけでは、Network 側でクライアントが参加する Solicited-Node マルチキャストアドレスに、WAN 側では誰も参加していない状態となる。

WAN Gateway が MLD Snooping を行っている場合、以下の問題が発生する:

1. WAN Gateway が NDP キャッシュを更新するために Solicited-Node マルチキャストアドレス宛に NS を送信
2. MLD Snooping により、そのマルチキャストグループのメンバーがいないため NS がどこにも転送されない
3. NS が届かないため NA が返らず、WAN Gateway の NDP キャッシュからエントリが削除される
4. 結果として通信が途絶える

### 本スクリプトが行うこと

本スクリプトは Network 側での DAD/NA を監視し、対応する Solicited-Node マルチキャストグループに WAN 側で参加する。これにより:

1. WAN Gateway が NS を UDM-Pro に転送できるようになる
2. UDM-Pro の NDP Proxy が NS を受信し NA を返す
3. 接続が維持される

## 動作原理

1. LAN 上の NS (DAD を含む) と NA を raw socket で監視
2. LAN 側ホストの IPv6 アドレスから Solicited-Node マルチキャストアドレス (`ff02::1:ffXX:XXXX`) を算出
3. WAN でそのマルチキャストグループに参加 (`IPV6_JOIN_GROUP`)
4. Kernel が自動的に MLDv2 Report を送信し、MLD Query にも応答する

これにより、WAN Gateway は UDM-Pro の WAN 側インターフェースを該当グループのメンバーとして認識し、 NS を UDM-Pro に転送する。 ndppd がその NS を受信して NA を返すことで、 LAN 側ホストの Neighbor Discovery が正常に機能する。

## 使い方

```
python3 mld_proxy.py <upstream_if> <downstream_if> [--fix-ndppd-ttl]
```

(要root)

### オプション

| オプション | 説明 |
|-----------|------|
| `--fix-ndppd-ttl` | ndppd の TTL を 30秒 から 3600秒 に延長し、ndppd を再起動する |

### 例

```bash
# 基本的な使い方
python3 mld_proxy.py eth9 br0

# ndppd TTL 修正付き
python3 mld_proxy.py eth9 br0 --fix-ndppd-ttl
```

### 出力例

```
MLD Proxy: br0 -> eth9
Listening for NDP on downstream...
Joined: ff02::1:ff12:3456 on eth9
Joined: ff02::1:ff78:9abc on eth9
```

## ルート優先度の自動調整

UDM-Pro の Single Network 構成では、WAN (eth9) と LAN (br0) に同一の IPv6 prefix が同じ metric で設定されることがある:

```
2001:db8:abcd::/64 dev eth9 proto ra metric 256
2001:db8:abcd::/64 dev br0 proto kernel metric 256
```

この状態で一部の Android 端末などで NUD (Neighbor Unreachability Detection) が失敗すると、br0 側のルートが消失し、UDM-Pro から LAN クライアントへのパケットが eth9 (WAN) に送出されてしまう問題がある。

本スクリプトは起動時および定期的にルーティングテーブルをチェックし、upstream と downstream で同一 prefix/metric のルートが存在する場合、downstream 側により低い metric のルートを自動的に追加する:

```
2001:db8:abcd::/64 dev br0 metric 128           ← 自動追加
2001:db8:abcd::/64 dev eth9 proto ra metric 256
2001:db8:abcd::/64 dev br0 proto kernel metric 256
```

これにより、LAN 側のルートが常に優先され、パケットが正しく br0 に送出される。

## ndppd TTL の延長 (Ubiquiti U7 対策)

Ubiquiti U7 シリーズの AP にはマルチキャストが正常に転送されない不具合があり、Android 端末などが NS (Neighbor Solicitation) を受け取れないことがある。この場合、ndppd のセッションが更新されず、upstream に NA を返さなくなり通信が途絶える。

`--fix-ndppd-ttl` オプションを使用すると、ndppd の設定ファイル (`/run/ndppd_{downstream}_{upstream}.conf`) の TTL を 30秒 (30000ms) から 3600秒 (3600000ms) に延長する。これにより:

1. ndppd のセッション有効期限が大幅に延長される
2. Android 端末が NS を受け取れる機会が増える
3. セッションが期限切れになりにくくなり、通信が安定する

設定ファイルが変更された場合、ndppd は自動的に再起動される (ubios-udapi-server が再起動を管理)。

## タイマー

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| `ADDR_TIMEOUT` | 1800 秒 | NDP トラフィックが観測されないアドレスを期限切れとする時間 |
| `EXPIRY_CHECK_INTERVAL` | 30 秒 | 期限切れチェックの実行間隔 |
| `NEIGHBOR_SCAN_INTERVAL` | 60 秒 | Neighbor テーブルスキャンの実行間隔 |
| `ROUTE_CHECK_INTERVAL` | 300 秒 | ルート優先度チェックの実行間隔 |
| `ROUTE_METRIC_DIVISOR` | 2 | 新しい metric = 元の metric / この値 |

## UniFi Dream Machine Pro でのデーモン化

UDM-Pro は再起動やファームウェア更新でカスタム設定が失われるため、[unifios-utilities](https://github.com/unifi-utilities/unifios-utilities) の `on-boot-script` を使用して永続化する。

### 1. on-boot-script のインストール

UDM-Pro に SSH 接続し、以下を実行:

```bash
curl -fsL "https://raw.githubusercontent.com/unifi-utilities/unifios-utilities/HEAD/on-boot-script/remote_install.sh" | /bin/bash
```

これにより `/data/on_boot.d/` に配置したスクリプトが起動時に自動実行されるようになる。

### 2. スクリプトの配置

```bash
# スクリプトを /data に配置
mkdir -p /data/mld-proxy
curl -o /data/mld-proxy/mld_proxy.py https://raw.githubusercontent.com/tnj/udm-pro-mld-proxy/mld_proxy.py
chmod +x /data/mld-proxy/mld_proxy.py
```

### 3. 起動スクリプトの作成

```bash
cat > /data/on_boot.d/10-mld-proxy.sh << 'EOF'
#!/bin/bash

SCRIPT_PATH="/data/mld-proxy/mld_proxy.py"
UPSTREAM_IF="eth9"      # WAN 側インターフェース
DOWNSTREAM_IF="br0"     # LAN 側インターフェース
PID_FILE="/run/mld-proxy.pid"
LOG_FILE="/var/log/mld-proxy.log"

# 既存プロセスの停止
if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null
    rm -f "$PID_FILE"
fi

# バックグラウンドで起動 (--fix-ndppd-ttl は Ubiquiti U7 環境で推奨)
nohup python3 "$SCRIPT_PATH" "$UPSTREAM_IF" "$DOWNSTREAM_IF" --fix-ndppd-ttl >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "MLD Proxy started (PID: $(cat $PID_FILE))"
EOF

chmod +x /data/on_boot.d/10-mld-proxy.sh
```

### 4. 動作確認

```bash
# 手動で起動スクリプトを実行
/data/on_boot.d/10-mld-proxy.sh

# ログを確認
tail -f /var/log/mld-proxy.log

# プロセスの確認
ps aux | grep mld_proxy
```

### 5. インターフェース名の確認

UDM-Pro のインターフェース名は環境により異なる場合がある。以下で確認:

```bash
ip link show
```

一般的な構成:
- WAN: `eth8` または `eth9`
- LAN (ブリッジ): `br0`

### 注意事項

- ファームウェアのメジャーアップデート後は on-boot-script の再インストールが必要な場合がある
