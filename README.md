# Software Factory (`sf`)

`herdr-core` + `agy` / `codex` / `pi` + `gh` 向けの自律ソフトウェアファクトリー・オーケストレーターです。

## 設計方針

- **ログは Cloudflare 側（`open-observability-framework`）に集約**: 生ログをローカル環境に保持せず、Cloudflare Workers / R2 / D1 上でサニタイズ・要約された Signal JSON v1 と Query Reference (`sf query`) のみを Pull します。
- **隔離ワークツリー実行**: 既存のチェックアウトには触れず、`~/.local/state/software-factory/work/<run-id>/` で作業します。
- **修正前の誤検知トリアージ＆敵対的診断検証**: `bugfix` / `efficiency` は実装前に原因調査・バックテストを行い、誤検知は `dismissed` で棄却。確定した仮説も別系統エージェントが反証（disprove）チェックしてから実装へ進みます。
- **2 段構えの承認ゲート**:
  1. **機械的リスク評価 (`sf evaluate-risk`)**: `feature` / `proposal`、変更ファイル数・行数超過、高リスクパス（認証・DB スキーマ・インフラ・公開契約等）、マニフェスト変更、`autoMerge.enabled=false` を決定論的にブロック。
  2. **独立エージェントレビュー (`sf review`)**: Worker とは別系統のエージェント（既定: Worker=`agy`, Reviewer=`codex`）が読み取り専用で差分検証し、`verdict == "approve"` かつ `behaviorImpact` が `none` / `low` の場合のみ `gh pr merge --auto --squash` を実行。
- **PR レビューコメント起点の再起動 & マージ後回復検証**: `human_review` 中に人間が PR コメントを書くと自動で Worker を再起動して修正を反映し、自動マージ後は `recoveryCheck` により Cloudflare 側メトリクスの回復を確認して `resolved` に閉じます。

## Cloudflare Signal Queue 契約 API（`open-observability-framework` 側）

`sf` は以下のエンドポイントを Cloudflare Access Service Token（`CF-Access-Client-Id` / `CF-Access-Client-Secret`）付きで呼び出します（別オリジンへのリクエストは拒否します）。

1. `GET <endpoint>/v1/signals?status=pending` — ペンディング Signal 一覧（`schemas/signal.v1.schema.json`）
2. `POST <endpoint>/v1/signals/<id>/ack` — 状態通知（`dismissed` / `auto_merged` / `human_review` / `resolved` / `recovery_failed`）
3. `GET <endpoint>/v1/queries/<id>` — `sf query <id>` でエージェントが必要時のみ取得するサニタイズ済み集計 API
4. `GET <endpoint>/v1/recovery/<id>` — マージ後の回復検証 API（`{"recovered": true|false, "summary": "..."}`）

## 主なコマンド

```bash
# 初期設定の生成 (~/.config/software-factory/config.json)
sf init \
  --signal-queue-endpoint https://oof.example.workers.dev \
  --credentials-file ~/.config/software-factory/cf-access.env

# 対象リポジトリを登録
sf repo add reta-ygs/my-app --auto-merge --ci-sensor --security-sensor --efficiency-sensor

# 新機能を手動投入（常に人間承認ゲート）
sf submit --repo reta-ygs/my-app --kind feature --title "Add export endpoint" --spec ./spec.md

# Cloudflare 側の集計 queryRef を参照
sf query q-1

# センサー巡回 & Cloudflare Signal Queue Pull
sf patrol

# 診断反証・PR 検知・リスク評価・独立レビュー・自動マージ・PR コメント再起動・回復検証を進行
sf reconcile

# ステータス確認
sf status
```
