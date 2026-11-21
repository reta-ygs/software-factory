# Software Factory (`sf`)

`coding` 環境（`herdr-core` + `agy` / `codex` / `pi` + `gh`）向けの自律ソフトウェアファクトリー・オーケストレーターです。

## 設計方針

- **ログは Cloudflare 側（`open-observability-framework`）に集約**: 生ログをローカル環境に保持せず、Cloudflare Workers / R2 / D1 上でサニタイズ・要約された Signal JSON v1 だけを Pull します。
- **隔離ワークツリー実行**: 既存のチェックアウトには触れず、`~/.local/state/software-factory/work/<run-id>/` で作業します。
- **2 段構えの承認ゲート**:
  1. **機械的リスク評価 (`sf evaluate-risk`)**: `feature` / `proposal`、変更ファイル数・行数超過、高リスクパス（認証・DB スキーマ・インフラ・公開契約等）、マニフェスト変更、`autoMerge.enabled=false` を決定論的にブロック。
  2. **独立エージェントレビュー (`sf review`)**: Worker とは別系統のエージェント（既定: Worker=`agy`, Reviewer=`codex`）が読み取り専用で差分検証し、`verdict == "approve"` かつ `behaviorImpact` が `none` / `low` の場合のみ `gh pr merge --auto --squash` を実行。

## Cloudflare Signal Queue 契約 API（`open-observability-framework` 側）

`sf patrol` は以下の 2 エンドポイントを Cloudflare Access Service Token（`CF-Access-Client-Id` / `CF-Access-Client-Secret`）付きで呼び出します。

1. `GET <endpoint>/v1/signals?status=pending`
   - レスポンス: `{"signals": [SignalV1, ...]}`（スキーマ: `schemas/signal.v1.schema.json`）
2. `POST <endpoint>/v1/signals/<id>/ack`
   - リクエストボディ: `{"status": "auto_merged" | "human_review", "runId": "...", "prUrl": "...", "reason": "...", "updatedAt": "..."}`

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

# 外部シグナルの手動インジェスト
cat signal.json | sf ingest -

# センサー巡回 & Cloudflare Signal Queue Pull
sf patrol

# 進行中ランの PR 検知・リスク評価・独立レビュー起動・自動マージ / エスカレーション
sf reconcile

# ステータス確認
sf status
```
