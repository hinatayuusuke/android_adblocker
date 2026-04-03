# Upstream Response Validation Fix Plan

## 概要

2026-03-31 の `UpstreamResolver` 変更後、正当な DNS 応答まで stale 扱いして捨てる可能性がある。
その結果、upstream failure が連続し、`scheduleNetworkReset()` と socket 再生成が多発して、体感上「頻繁にクラッシュする」状態を引き起こしている疑いが強い。

本ドキュメントでは、応答照合を DNS 仕様に沿って緩和しつつ、遅延応答の誤配送防止という元の目的を維持する修正案をまとめる。

---

## 原因仮説

### 1. Question の生バイト完全一致が厳しすぎる

現状の `UpstreamResolver.responseMismatchReason()` は、以下をすべて満たしたときだけ成功扱いにしている。

* DNS ID が一致する
* `QDCOUNT >= 1`
* 応答の Question 領域が parse できる
* 応答の Question の生バイト列が元クエリと完全一致する

しかし DNS 応答では、以下の差異があっても正当な応答になり得る。

* QNAME の大文字小文字差
* Question 表現の差異
* 実装依存の Question 圧縮

このため、正当応答を `question_mismatch` または `question_parse` として破棄し、最終的に timeout/failure 扱いになる可能性がある。

### 2. failure 連続時の reset が過敏に発火する

`DnsVpnService` 側では upstream success 以外をすべて failure と見なし、連続閾値到達で reset をかけている。

* 失敗 3 回で `UPSTREAM_FAIL_RESET`
* `handleNetworkChange()` で request/response queue を clear
* upstream socket を shutdown して再生成

照合の誤判定が多いと、ネットワーク異常ではないのに reset が連鎖し、サービス不安定化につながる。

---

## 修正方針

### 方針 1. 照合条件を「DNS ID + 質問の意味一致」に変更する

生バイト完全一致はやめて、以下で判定する。

* `ID` 一致
* `QDCOUNT >= 1`
* 応答 Question を parse できる
* `QTYPE` 一致
* `QCLASS` 一致
* `QNAME` 一致
  * ASCII 英字は大小無視

これにより、元の目的である「別クエリの遅延応答を受け入れない」は維持しつつ、表現差による誤廃棄を減らせる。

### 方針 2. Question compression を parse 可能にする

少なくとも以下のどちらかを採る。

* 推奨: Question parser を compression pointer 対応にする
* 最低限: pointer を即 reject せず、`ID` と `QTYPE/QCLASS` の整合を優先して扱う

DNS 実装差を考えると、pointer 全拒否は危険。

### 方針 3. mismatch 理由を細分化してログで判別可能にする

ログで次を区別できるようにする。

* `id_mismatch`
* `question_name_mismatch`
* `question_type_mismatch`
* `question_class_mismatch`
* `question_parse`
* `short_packet`

`question_mismatch` だけだと、実際に何がずれているか分からない。

### 方針 4. reset の発火条件は今回は据え置き

まずは照合誤判定を減らすのが先。
reset 閾値や worker 数の調整は副次対応とし、一次修正ではロジックの本質原因に絞る。

---

## 具体修正案

### A. `UpstreamResolver`

変更内容:

* `expectedQuestion: ByteArray` の比較を廃止し、比較用の構造化データを受け取る
* 例: `expectedName`, `expectedType`, `expectedClass`
* 応答側も同様に Question を parse して意味比較する
* QNAME は lower-case 正規化して比較する
* compression pointer を parse できるようにする

実装イメージ:

* `resolve(query, expectedQueryId, expectedQuestion)` を
  `resolve(query, expectedQueryId, expectedName, expectedType, expectedClass)` に変更
* `responseMismatchReason()` は Question を parse して構造比較

### B. `DnsPacketProcessor`

変更内容:

* `DnsQuery` は既に `domain`, `qtype`, `qclass` を持っているため、それを `UpstreamResolver` に渡す
* `question: ByteArray` は SERVFAIL/blocked response の構築には維持してよい

### C. `DnsVpnService`

変更内容:

* `resolver.resolve(...)` 呼び出し引数を `job.query.domain`, `job.query.qtype`, `job.query.qclass` ベースに変更
* stale discard のログ増加時に原因内訳を見やすくする

---

## 検証項目

### 1. 期待する改善

* `UPSTREAM_STALE_RESPONSE_DISCARD reason=question_mismatch` が大幅に減る
* `UPSTREAM_OK` が回復する
* `UPSTREAM_FAIL_RESET threshold hit` の頻度が下がる
* 体感上の「クラッシュ」が再現しにくくなる

### 2. 確認ログ

優先して見るログ:

* `UpstreamResolver`
* `DnsVpnService`
* `AndroidRuntime`

確認したいパターン:

* 修正前
  * `UPSTREAM_STALE_RESPONSE_DISCARD`
  * `UPSTREAM_FAIL_FINAL`
  * `UPSTREAM_FAIL_RESET threshold hit`
  * `NET_RESET_EXECUTE`
* 修正後
  * `UPSTREAM_OK`
  * stale discard が `id_mismatch` 中心になる
  * reset 連鎖が止まる

### 3. 回帰確認

以下は維持される必要がある。

* 遅延した別クエリ応答を受け入れない
* failover 自体は継続して動く
* timeout budget の総量は現行どおり

---

## リスク

### リスク 1. 緩和しすぎると誤配送を再導入する

対策:

* `ID` 一致は必須
* `QNAME/QTYPE/QCLASS` の意味一致も必須

### リスク 2. compression parser の不備で別の誤判定を生む

対策:

* pointer 深さ上限を設ける
* packet length 境界チェックを厳密に行う
* parse failure は従来どおり discard する

---

## 今回の実装優先順位

1. `question` 生バイト完全一致をやめる
2. `QNAME/QTYPE/QCLASS` 比較へ変更する
3. compression pointer を扱える parser を入れる
4. mismatch reason を細分化する
5. 必要なら追加で reset 閾値を再評価する

---

## Definition of Done

* 正当応答が `question_mismatch` / `question_parse` で大量 discard されない
* `UPSTREAM_FAIL_RESET` の頻度が目に見えて減る
* 既存の stale response 誤配送防止は維持される
* 実機ログで `FATAL EXCEPTION` が出ていない場合でも、VPN 自壊ループが止まったことを確認できる
