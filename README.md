# kakuremichi（隠れ道）Agent
## About
kakuremichi のエッジクライアント。Control と WebSocket で接続し、指示された Gateway へ WireGuard で閉域網を張り、ローカル HTTP サービスをトンネル公開する。

## できること
- Control からの設定更新を受信し、WireGuard 仮想 NIC を生成・更新
- netstack 上のローカルリバースプロキシで、ドメインごとに内部サービスへ転送
- API キーによる認証、WireGuard 鍵の自動生成と永続化（`wireguard.key`）

## 必要環境
- Go 1.24.x
- Control サーバーが起動済みで API キーを発行できること

## クイックスタート
1. `.env.example` をコピーして値を入れる:
   ```bash
   cp .env.example .env
   # CONTROL_URL, API_KEY を設定
   ```
2. 実行:
   ```bash
   go run ./cmd/agent \
     --control-url=ws://localhost:3001 \
     --api-key=agt_your_api_key_here
   ```
   - `WIREGUARD_PRIVATE_KEY` を指定しない場合、起動時に `wireguard.key` として生成・保存。
   - 初回に Control から Gateway/トンネル設定を受け取ると WireGuard デバイスとローカルプロキシが立ち上がる。

### コンフィグ（環境変数/フラグ）
- `CONTROL_URL` / `--control-url` : Control への WebSocket URL（例: `ws://localhost:3001`）
- `API_KEY` / `--api-key` : Control で発行したエージェント用 API キー（必須）
- `WIREGUARD_PRIVATE_KEY` / `--wireguard-private-key` : 既存キーを使いたい場合に指定
- `DOCKER_ENABLED` / `--docker-enabled` : Docker 連携を有効にするフラグ（デフォルト false）
- `DOCKER_SOCKET` / `--docker-socket` : Docker ソケットパス（デフォルト `/var/run/docker.sock`）

## 開発
- Dev Containerを推奨
- テスト: `go test ./...`
- ローカルビルド: `go build ./cmd/agent`
- Docker イメージ:
  ```bash
  docker build -f Dockerfile.dev -t kakuremichi-agent-dev .
  ```

## プロジェクト構成
- `cmd/agent` : エントリポイント
- `internal/config` : フラグ/環境変数ロード
- `internal/ws` : Control との WebSocket クライアント
- `internal/wireguard` : デバイス設定と鍵管理
- `internal/proxy` : netstack 上のローカル HTTP リバースプロキシ

## メモ
- WireGuard キーはリポジトリ直下に保存されるため、共有したくない場合は `.gitignore` 等で除外するか、パスを変えて運用してください。
