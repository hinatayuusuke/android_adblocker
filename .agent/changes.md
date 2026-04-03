## 2026-01-08 11:17 (Asia/Taipei) — DNS-only VPN MVP 実装

### Summary
- DNS-only VPNで広告ドメインを遮断する最小構成を追加

### Context / Goal
- doc/plan.md の設計方針に沿って広告ブロックを実装
- Android端末内でDNSレベルの遮断を行えるようにする

### Changes
- Flutter UIにVPNの開始/停止と許可リスト管理を追加
- VpnServiceベースのDNSフィルタ処理と上流DNS転送を実装
- Android権限/サービス宣言とサンプルブロックリストを追加

### Files Touched
- lib/main.dart — VPN制御と許可リスト編集の画面を追加
- Android/app/src/main/AndroidManifest.xml — VPNサービスと必要権限を追加
- Android/app/src/main/kotlin/com/example/android_adblocker/MainActivity.kt — MethodChannel経由のVPN制御を実装
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — DNS-only VPNサービスとDNS処理を追加
- Android/app/src/main/assets/blocklist.txt — サンプルブロックリストを追加
- .agent/changes.md — 変更記録を追記

### Behavioral Impact
- VPNを有効化するとDNSクエリがローカルで評価され、ブロック対象はNXDOMAINで拒否される
- 許可リストに登録したドメインはブロック対象でも通過する

### Risk & Mitigation
- Risk: DNS応答の遅延や誤ブロックでアプリ通信に影響が出る可能性
- Mitigation: 許可リストで例外指定でき、停止ボタンで即時解除できる

### Tests / Verification
- 未実施（実機でのVPN許可と通信確認が必要）
## 2026-01-08 11:23 (Asia/Taipei) — 変更記録の書式修正

### Summary
- changes.mdのファイル参照行に出た制御文字を修正する追記を追加

### Context / Goal
- 変更記録の可読性を回復する
- 既存エントリの改変を避けつつ補足を残す

### Changes
- 変更記録の正しいパス表記を追記

### Files Touched
- `.agent/changes.md` — 書式補正の追記を追加

### Behavioral Impact
- 実行時の挙動変更はなし

### Risk & Mitigation
- Risk: 変更記録が冗長になる可能性
- Mitigation: 補正内容を最小限に留める

### Tests / Verification
- 未実施（記録の追記のみ）
## 2026-01-08 11:26 (Asia/Taipei) — Webビルド互換の調整

### Summary
- Web環境でのdart:io依存を避けるための判定ロジックを追加

### Context / Goal
- FlutterのWebターゲットでもビルドできる状態にする
- Android以外ではVPN機能を無効化する

### Changes
- Android判定にkIsWebとdefaultTargetPlatformを採用

### Files Touched
- `lib/main.dart` — Android判定をdart:ioからfoundationベースに変更
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- Web/非Android環境でアプリ起動時にクラッシュせず、機能は非対応として表示される

### Risk & Mitigation
- Risk: プラットフォーム判定の条件漏れ
- Mitigation: kIsWebとTargetPlatformを組み合わせて判定

### Tests / Verification
- 未実施（Webビルド環境での確認が必要）
## 2026-01-08 11:26 (Asia/Taipei) — ログタグの定数化

### Summary
- DnsVpnServiceのログタグ定数を追加

### Context / Goal
- ログ出力の識別子を明示して運用性を上げる
- 未定義のTAG参照を解消する

### Changes
- TAG定数をDnsVpnServiceのcompanion objectに追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt` — ログタグ定数を追加
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- 実行時の挙動変更はなし（ログ表記のみ）

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（ログ出力の整理のみ）
## 2026-01-08 11:27 (Asia/Taipei) — Docstring補足

### Summary
- DnsVpnServiceのpublicメソッドにDocstringを追加

### Context / Goal
- コメント規約に合わせてpublicメソッドの説明を補完する
- 仕様変更時の意図を残す

### Changes
- onCreateに目的・副作用を記述したDocstringを追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt` — onCreateのDocstringを追加
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- 実行時の挙動変更はなし

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（コメント追加のみ）
## 2026-01-13 13:17 (Asia/Taipei) — Activity互換修正

### Summary
- FlutterFragmentActivityへ切り替えてActivity Result APIを有効化

### Context / Goal
- registerForActivityResultの未解決エラーを解消する
- VPN許可フローを維持したままビルドを通す

### Changes
- MainActivityの継承元をFlutterFragmentActivityに変更

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/MainActivity.kt` — FlutterFragmentActivityへ切り替え
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- VPN権限の要求フローが正常に動作する

### Risk & Mitigation
- Risk: 既存のActivity挙動が変わる可能性
- Mitigation: FlutterFragmentActivityはFlutterActivityと互換のフラグメントベース実装

### Tests / Verification
- 未実施（Androidビルドの確認が必要）
## 2026-01-13 13:28 (Asia/Taipei) — FGS種別の指定

### Summary
- VPNサービスのFGS種別をspecialUseで宣言し、startForeground時にも種別を指定

### Context / Goal
- targetSdk 36でMissingForegroundServiceTypeExceptionが発生するため対処
- VPN開始時にクラッシュしないようにする

### Changes
- ManifestにspecialUseのforegroundServiceTypeと権限、subtypeを追加
- startForegroundにFGS種別を指定する分岐を追加

### Files Touched
- `android/app/src/main/AndroidManifest.xml` — FGS種別と権限、subtypeを追加
- `android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt` — startForegroundにFGS種別指定を追加
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- VPN開始時にFGS種別未指定で落ちる問題が解消される

### Risk & Mitigation
- Risk: 特定OSでFGS種別の扱い差が出る可能性
- Mitigation: API 34未満は従来のstartForegroundを使用

### Tests / Verification
- 未実施（実機でVPN開始の確認が必要）
## 2026-01-13 15:15 (Asia/Taipei) — READMEとMITライセンス作成

### Summary
- GitHub向けREADMEとMITライセンスを整備

### Context / Goal
- 現状仕様を英語で文書化する
- 公開に必要なライセンス表記を追加する

### Changes
- README.mdを仕様説明/使い方/制約の内容で更新
- MIT LicenseをLICENSEとして追加

### Files Touched
- `README.md` — 英語READMEに更新
- `LICENSE` — MITライセンスを追加
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- 実行時の挙動変更はなし

### Risk & Mitigation
- Risk: ライセンスの権利者表記が仮置き
- Mitigation: 必要なら正式な著作権者名に差し替える

### Tests / Verification
- 未実施（ドキュメント更新のみ）
## 2026-01-13 17:51 (Asia/Taipei) — 長時間稼働レビュー

### Summary
- 長時間起動の観点でコードレビュー結果を追加

### Context / Goal
- VPNサービスの長時間稼働時のリスクを洗い出す
- 改善ポイントを文書化する

### Changes
- doc/Review.md にレビュー結果を記載

### Files Touched
- `doc/Review.md` — 長時間稼働のコードレビューを追加
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- 実行時の挙動変更はなし

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（ドキュメント追加のみ）
## 2026-01-13 18:00 (Asia/Taipei) — 長時間起動の安定化

### Summary
- FGS開始前の重い処理を後ろに回し、パケットループ異常終了時に停止するよう修正

### Context / Goal
- 長時間起動時に起動遅延や無反応状態が起きるリスクを下げる
- 監視ループが落ちた際にサービス状態を正しく更新する

### Changes
- ブロックリスト読込をFGS開始後の別スレッドに移動
- パケットループ終了時にサービス停止を行う処理を追加
- ブロックリスト更新メソッドを追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt` — FGS起動順と異常終了処理を改善
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- VPN開始がタイムアウトしにくくなり、ループ異常終了時は自動停止される

### Risk & Mitigation
- Risk: 起動直後はブロックリストが空の短い時間がある
- Mitigation: 読込完了後に即時反映される

### Tests / Verification
- 未実施（実機での長時間動作確認が必要）

**2026-01-14 10:02 (Asia/Taipei) — VPN取消時の停止処理追加**

### Summary
- VPN権限の取り消し時にリソース解放と状態更新を行う

### Context / Goal
- 長時間稼働中のVPN取り消しで状態が残る問題を防ぐ
- UIと内部状態の不整合を避ける

### Changes
- onRevokeでstopVpnを呼び出してクリーンアップするように追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt` — onRevokeを追加して停止処理を実装

### Behavioral Impact
- VPNがシステムから取り消された場合に即時停止し、状態が同期される

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（ロジック追加のみ）

**2026-01-14 10:17 (Asia/Taipei) — DNS上流解決の非同期化**

### Summary
- 上流DNS解決をキュー/ワーカープールへ分離し、タイムアウト時はSERVFAILで返す

### Context / Goal
- 長時間稼働時のDNS詰まりを抑える
- TUN読み取りをブロックさせない

### Changes
- 上流解決をワーカープールとキューに移行
- 応答書き込みを専用スレッドに分離し、キュー満杯時はSERVFAILを即時返す
- ワーカーごとに上流ソケットを分離

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt` — ワーカープール化とSERVFAIL応答を追加

### Behavioral Impact
- 上流遅延時もTUN読み取りが継続し、タイムアウトはSERVFAILで返る

### Risk & Mitigation
- Risk: キュー満杯時に一部のDNS応答が失敗する
- Mitigation: SERVFAILで即時返すため、クライアント側の再試行で回復できる

### Tests / Verification
- 未実施（実機で長時間通信の確認が必要）
**2026-01-14 14:27 (Asia/Taipei) — handlePacket copyOfRange削減**

### Summary
- handlePacketのアドレス/クエリコピーを抑制して割り当てを削減

### Context / Goal
- パケット処理のホットパスのGC負荷を下げる
- doc/PerformancePlan.mdの1-1に沿ってcopyOfRangeを最小化する

### Changes
- IPv4アドレスをIntで保持して配列コピーを削減
- DNSクエリは上流送信時のみペイロードをコピーするよう変更
- parseQueryをオフセット/長さ指定で読むように更新

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — handlePacketのアロケーション削減とIPv4アドレス処理を更新

### Behavioral Impact
- DNSパケット処理の割り当てが減り、GC負荷が軽減される

### Risk & Mitigation
- Risk: IPv4アドレスの順序変換が誤ると応答先が変わる
- Mitigation: 既存の送信元/送信先の入れ替え順に合わせてオフセットを固定

### Tests / Verification
- 未実施（性能観測は実機での継続通信が必要）
**2026-01-14 15:11 (Asia/Taipei) — DNSドメイン正規化の割り当て削減**

### Summary
- parseQueryで小文字化し、handlePacketのlowercase/trimEndを除去

### Context / Goal
- ホットパスでのString生成を抑えてGC負荷を減らす
- PerformancePlan 1-2の実装を進める

### Changes
- DNSラベル読取時にASCII小文字化して正規化ドメインを生成
- handlePacketのlowercase()/	rimEnd()を削除

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — ドメイン正規化をparseQuery内へ移動

### Behavioral Impact
- ドメイン判定前のString生成が減り、性能が向上する可能性がある

### Risk & Mitigation
- Risk: 非ASCIIラベルの変換処理で文字化けが発生する
- Mitigation: 非ASCIIはUTF-8デコード経由で保持する

### Tests / Verification
- 未実施（実機でDNS問い合わせを確認する必要がある）
**2026-01-14 15:36 (Asia/Taipei) — ドメイン構築の割り当て削減**

### Summary
- DNSクエリ解析でlabels Listを廃止しStringBuilderでドメインを構築

### Context / Goal
- パケット処理のホットパスでの割り当てをさらに削減する
- PerformancePlan 1-3の実装を進める

### Changes
- parseQueryでStringBuilderに直接ドメインを構築
- labels ListとjoinToStringの割り当てを削除

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — ドメイン生成をStringBuilderに変更

### Behavioral Impact
- ドメイン組み立て時の割り当てが減り、GC負荷が軽減される

### Risk & Mitigation
- Risk: ラベル境界の区切り処理ミスでドメインが崩れる
- Mitigation: 先頭以外のみ.を挿入するロジックに限定

### Tests / Verification
- 未実施（実機でDNS問い合わせの動作確認が必要）
**2026-01-14 15:50 (Asia/Taipei) — UpstreamResolverのバッファ再利用**

### Summary
- UpstreamResolverでバッファとDatagramPacketを使い回すよう変更

### Context / Goal
- 上流DNS解決の割り当てを削減してGC負荷を下げる
- PerformancePlan 3-1の実装を進める

### Changes
- UpstreamResolverに固定バッファ/パケットを保持して再利用
- resolve内の毎回生成を削除

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — UpstreamResolverのバッファ/パケット再利用

### Behavioral Impact
- 上流問い合わせ処理の割り当てが減り、性能が向上する可能性がある

### Risk & Mitigation
- Risk: 受信パケット長を誤って扱うと応答が欠ける
- Mitigation: receive後のlengthに基づいてcopyOfする

### Tests / Verification
- 未実施（実機でDNS問い合わせの動作確認が必要）
**2026-01-14 16:02 (Asia/Taipei) — 応答キューのバッチ書き込み**

### Summary
- responseWriterでdrainToを使い応答書き込みをまとめた

### Context / Goal
- 応答キューのロック取得回数とwrite回数を減らして性能を改善する
- PerformancePlan 4-1の実装を進める

### Changes
- responseWriterでバッチ取り出しと連続書き込みを実装
- バッチ上限定数を追加

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — responseWriterのバッチ処理を追加

### Behavioral Impact
- 応答の書き込みがまとめて行われ、負荷が軽減される可能性がある

### Risk & Mitigation
- Risk: バッチ処理で応答が遅延する可能性がある
- Mitigation: バッチ上限を小さく保ち、takeで即時に先頭を取得

### Tests / Verification
- 未実施（実機で通信遅延の体感確認が必要）
**2026-01-14 16:12 (Asia/Taipei) — ドメイン判定のsubstring廃止**

### Summary
- 逆順トライでドメイン判定を行いsubstringループを削除

### Context / Goal
- matchesでのsubstring生成を無くしてGC負荷を減らす
- PerformancePlan 2-1の改善案を実装する

### Changes
- DomainRuleMatcherに逆順トライを導入してsuffix一致判定を実装
- allowlist/blocklist更新時にトライを再構築

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/DnsVpnService.kt — DomainRuleMatcherを逆順トライに変更

### Behavioral Impact
- ドメイン一致判定時の割り当てが減り、性能が向上する可能性がある

### Risk & Mitigation
- Risk: ラベル境界判定の誤りで誤ブロック/すり抜けが起きる
- Mitigation: 終端か直前が'.'の場合のみ一致とするロジックに限定

### Tests / Verification
- 未実施（実機でブロック/許可の挙動確認が必要）
**2026-01-15 09:47 (Asia/Taipei) — リファクタリング: 責務分離**

### Summary
- God Class化していたDNS処理をcore/net/data/serviceへ分割

### Context / Goal
- doc/RefactoringPlan.mdに沿ってロジックとI/Oを分離する
- テスト容易性と保守性を高める

### Changes
- DnsPacketProcessor/DomainRuleMatcher/DomainSuffixTrieをcoreへ分離
- UpstreamResolverをnetへ、BlocklistLoader/VpnPreferencesをdataへ分離
- DnsVpnServiceをserviceパッケージに移動し参照/manifestを更新

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — サービス本体を移動し依存を整理
- Android/app/src/main/kotlin/com/example/android_adblocker/core/DnsPacketProcessor.kt — パケット処理を分離
- Android/app/src/main/kotlin/com/example/android_adblocker/core/DomainRuleMatcher.kt — ルール判定を分離
- Android/app/src/main/kotlin/com/example/android_adblocker/core/DomainSuffixTrie.kt — トライ構造を分離
- Android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt — 上流DNS通信を分離
- Android/app/src/main/kotlin/com/example/android_adblocker/data/BlocklistLoader.kt — ブロックリスト読込を分離
- Android/app/src/main/kotlin/com/example/android_adblocker/data/VpnPreferences.kt — 設定キーを分離
- Android/app/src/main/kotlin/com/example/android_adblocker/MainActivity.kt — 新パッケージ参照に更新
- Android/app/src/main/AndroidManifest.xml — サービスのパスを更新
- README.md — 参照パスを更新

### Behavioral Impact
- 機能挙動は同一で、構成のみ変更

### Risk & Mitigation
- Risk: パッケージ変更の参照漏れで起動時にクラッシュする
- Mitigation: MainActivity/Manifest/READMEの参照を更新

### Tests / Verification
- 未実施（ビルド/実機での起動確認が必要）
**2026-01-15 13:28 (Asia/Taipei) — ネットワーク変化時の上流再生成**

### Summary
- ネットワーク変化検知で上流ソケット再作成とキュークリアを行う

### Context / Goal
- 圏外復帰や回線切替時のDNS詰まりを早期に解消する
- doc/Bugfix.mdの対策案1を実装する

### Changes
- ConnectivityManagerのNetworkCallbackで変化を検知
- 変化時に上流ワーカー/ソケットを再起動しキューをクリア

### Files Touched
- Android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — ネットワーク監視と上流再作成を追加

### Behavioral Impact
- ネットワーク切替後の滞留リクエストを破棄し、新規上流ソケットで再開する

### Risk & Mitigation
- Risk: 変化通知が連続すると再起動が過剰になる
- Mitigation: 同期ロックで再生成を直列化

### Tests / Verification
- 未実施（圏外復帰やWi-Fi/モバイル切替の実機検証が必要）
**2026-01-15 13:48 (Asia/Taipei) — ネットワーク状態権限の追加**

### Summary
- ConnectivityManager使用に必要なACCESS_NETWORK_STATEを追加

### Context / Goal
- NetworkCallback登録時のSecurityExceptionでアプリが落ちる問題を解消する
- doc/Bugfix.mdに基づくネットワーク監視を安定動作させる

### Changes
- AndroidManifestにACCESS_NETWORK_STATEを追加

### Files Touched
- Android/app/src/main/AndroidManifest.xml — 権限追加

### Behavioral Impact
- ネットワーク監視が許可され、サービス起動時のクラッシュが解消される

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（Android Studioでの起動確認が必要）
**2026-01-16 09:44 (Asia/Taipei) — デバッグログ追加**

### Summary
- UpstreamResolverとキュー処理にデバッグログを追加

### Context / Goal
- doc/Debuglog.mdに沿って原因特定のためのログを拡充する
- DNS遅延の兆候を把握できるようにする

### Changes
- UpstreamResolverで受信前後のlengthと所要時間をログ出力
- SERVFAIL発生数と応答キュー破棄数のカウントログを追加

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt — 受信長と遅延のデバッグログを追加
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — SERVFAIL/応答破棄のカウントログを追加

### Behavioral Impact
- Debugビルドでログが増える（リリース時はBuildConfig.DEBUGで抑制）

### Risk & Mitigation
- Risk: ログ量増加でデバッグ時の負荷が上がる
- Mitigation: DEBUGフラグで制御し、通常運用では無効化

### Tests / Verification
- 未実施（ログの出力確認が必要）
**2026-01-16 09:54 (Asia/Taipei) — BuildConfig生成の有効化**

### Summary
- BuildConfigを生成するためbuildFeaturesを有効化

### Context / Goal
- デバッグログ追加時のBuildConfig参照エラーを解消する
- Android Studioのビルド失敗を修正する

### Changes
- appのbuild.gradle.ktsにbuildFeatures.buildConfigを追加

### Files Touched
- ndroid/app/build.gradle.kts — BuildConfig生成を有効化

### Behavioral Impact
- BuildConfigが生成され、DEBUGフラグ参照が可能になる

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（Android Studioでのビルド確認が必要）**2026-01-16 09:56 (Asia/Taipei) — BuildConfig参照の定数化修正**

### Summary
- BuildConfig.DEBUGをconstからvalに変更してコンパイルエラーを解消

### Context / Goal
- Kotlinのconst制約によりビルドが失敗する問題を修正する
- デバッグログの条件分岐を維持する

### Changes
- DEBUG_LOGSをconstからvalへ変更

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt — DEBUG_LOGSの定義を修正
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — DEBUG_LOGSの定義を修正

### Behavioral Impact
- Debug/Releaseでのログ制御は維持される

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（Android Studioでのビルド確認が必要）

**2026-01-16 10:03 (Asia/Taipei) — DatagramPacket lengthの復元**

### Summary
- UpstreamResolverの受信前にDatagramPacket.lengthを最大値へ戻す

### Context / Goal
- 長時間起動後のDNS応答欠損による遅延を防ぐ
- doc/Consolelog.mdで確認したlength縮小を解消する

### Changes
- receive()直前でresponsePacket.lengthをリセット

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt — lengthの復元処理を追加

### Behavioral Impact
- DNS応答が途中で切れず、再試行による遅延が減る

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（長時間動作でログ確認が必要）

**2026-01-16 10:44 (Asia/Taipei) — requestQueueの短時間待機**

### Summary
- requestQueue満杯時に短時間待機してSERVFAILを減らす

### Context / Goal
- 瞬間的なスパイクでの不要なSERVFAILを抑制する
- キュー満杯時のリトライ嵐を軽減する

### Changes
- requestQueue.offerに短時間タイムアウトを追加
- 待機時間の定数を追加

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — offer待機と定数/TimeUnit追加

### Behavioral Impact
- キュー一時満杯時のSERVFAILが減る可能性がある

### Risk & Mitigation
- Risk: 読み取りループがわずかに遅延する
- Mitigation: 待機時間を10msに抑制

### Tests / Verification
- 未実施（高負荷時の挙動確認が必要）**2026-01-16 10:51 (Asia/Taipei) — requestQueue待機定数の追加**

### Summary
- REQUEST_QUEUE_WAIT_MSをcompanion objectに追加

### Context / Goal
- offer(timeout)で参照する定数未定義によるビルドエラーを解消する

### Changes
- companion objectにREQUEST_QUEUE_WAIT_MSを追加

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — 定数追加

### Behavioral Impact
- ビルドが通り、短時間待機が有効になる

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（Android Studioでのビルド確認が必要）**2026-01-16 12:37 (Asia/Taipei) — Add startup debug logs**

### Summary
- Add debug timestamps around VPN establish and packet loop readiness plus upstream IO error logs.

### Context / Goal
- Provide evidence for startup race and SERVFAIL timing during first launch.
- Surface upstream IO failures during early DNS resolution.

### Changes
- Log establish completion time and packet loop start/ready timings in debug builds.
- Include time-since-establish on SERVFAIL fallback logs.
- Log upstream IO exceptions when debug logging is enabled.

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — add debug timestamps for establish/packet loop and enrich SERVFAIL logs.
- ndroid/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt — log upstream IOException details in debug builds.

### Behavioral Impact
- Debug builds emit additional timing/error logs; runtime behavior unchanged.

### Risk & Mitigation
- Risk: Log noise/perf overhead in debug sessions.
- Mitigation: Logs guarded by BuildConfig.DEBUG.

### Tests / Verification
- 未実施（ログ追加のみ）**2026-01-16 13:43 (Asia/Taipei) — Reduce socket resets on capability changes**

### Summary
- Avoid resetting upstream sockets on capability-only network updates.

### Context / Goal
- Prevent frequent socket resets triggered by signal strength/bandwidth updates.
- Reset only when the actual default network changes or is lost.

### Changes
- Track the current network and ignore redundant capability callbacks.
- Reset sockets only on real network switches or loss.

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — track current network and gate socket resets.

### Behavioral Impact
- Fewer upstream socket resets during transient capability updates.

### Risk & Mitigation
- Risk: Missed reset if platform reports changes only via capabilities on the same Network instance.
- Mitigation: Still update on onAvailable/onLost and onCapabilitiesChanged when the Network instance changes.

### Tests / Verification
- 未実施（ログ確認は実機で実施）
  
- **2026-01-19 09:53 (Asia/Taipei) — Defer network resets when idle**

### Summary
- Gate upstream socket resets to active DNS traffic windows.

### Context / Goal
- Reduce power use by skipping network reset work during idle periods.
- Apply deferred resets when DNS traffic resumes.

### Changes
- Track last packet time and defer network resets when idle.
- Apply pending resets on next packet read.
- Add a configurable idle threshold for resets.

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — defer network reset handling to active traffic windows and track pending resets.

### Behavioral Impact
- Network changes during idle no longer immediately reset upstream sockets; reset happens on next DNS activity.

### Risk & Mitigation
- Risk: First query after idle may see a slight delay due to deferred reset.
- Mitigation: Reset is applied before processing the first active packet.

### Tests / Verification
- 未実施（実機ログで挙動確認が必要）
**2026-01-20 09:47 (Asia/Taipei) — responseWriter監視の追加**

### Summary
- responseWriter異常時の停止処理と監視を追加

### Context / Goal
- doc/Bugfix3.mdの対策案に従い、応答書き込み停止を検知して復旧できるようにする
- responseWriterのIOExceptionや停止状態を検出してVPNを停止する

### Changes
- responseWriterのIOException発生時に致命停止を要求し、読み取りループ経由でstopVpnへ落とす
- responseWriterの生存/書き込み停滞を監視するwatchdogスレッドを追加
- 応答書き込み時刻の追跡と監視用タイムアウト定数を追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — responseWriter異常時の停止処理とwatchdog監視を追加

### Behavioral Impact
- responseWriterが落ちた/応答が書けない状態を検知するとVPNサービスが停止する

### Risk & Mitigation
- Risk: 低負荷時や一時的な遅延で誤停止する可能性
- Mitigation: 応答キューに滞留がある場合のみ監視し、タイムアウトを設定

### Tests / Verification
- 未実施（実機での長時間動作確認が必要）
**2026-01-22 09:59 (Asia/Taipei) — 再起動クールダウンとwatchdog緩和**

### Summary
- responseWriter監視の誤検知を抑えつつ再起動ループを防止

### Context / Goal
- watchdog起点の連続停止がUIフリーズに見える問題を抑える
- 過敏な監視と即時再起動を避けて安定化する

### Changes
- responseWriterの停滞判定に連続検知カウントを導入
- 再起動クールダウン時間を設け、短時間の再起動ループを抑制
- 応答書き込みの進行で停滞カウントをリセット

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — watchdog緩和と再起動クールダウンを追加

### Behavioral Impact
- responseWriter停滞時の停止が連続検知条件になり、短時間の再起動連発を抑える

### Risk & Mitigation
- Risk: 監視緩和により応答停止から復旧までの検出が遅れる可能性
- Mitigation: 連続検知と閾値を調整可能な定数に集約

### Tests / Verification
- 未実施（実機で再起動ループが収まるかの確認が必要）
**2026-01-22 11:06 (Asia/Taipei) — Bugfix4提案の反映**

### Summary
- クールダウン通知、ネットワーク切替対策、スレッド収束ログを追加

### Context / Goal
- doc/Bugfix4.mdの提案順に基づき、再起動ループと切替時不安定のリスクを下げる
- 停止検知時の情報を強化して原因切り分けを容易にする

### Changes
- クールダウン残り時間をMethodChannelで返し、UI側にエラーとして伝達
- 上流ソケットを現在のネットワークへバインドし、切替時にrequestQueueも破棄
- スレッド停止時にjoinを実行して残存スレッドを警告、fatal stop時の詳細ログを追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — クールダウン共有、ネットワークバインド、キュー破棄、join、詳細ログを追加
- `android/app/src/main/kotlin/com/example/android_adblocker/MainActivity.kt` — クールダウン中の開始要求をエラー返却

### Behavioral Impact
- クールダウン中の開始はUIにエラー表示され、上流切替後の古いDNS要求は破棄される

### Risk & Mitigation
- Risk: クールダウン通知が厳しすぎると開始を遅らせる可能性
- Mitigation: クールダウンは定数化しており調整可能

### Tests / Verification
- 未実施（実機で切替とクールダウン通知の確認が必要）
**2026-01-22 13:21 (Asia/Taipei) — 省電力運用の実装案**

### Summary
- 画面オフ時に上流解決を抑制/遅延する省電力案をDocに整理

### Context / Goal
- VPN継続を前提に、アイドル時の消費電力を下げる設計案を示す
- watchdog緩和と再起動クールダウンは維持する

### Changes
- アイデル判定と上流解決抑制の実装方針を整理
- 影響/リスクと調整可能な定数の指針を記載

### Files Touched
- `doc/EcoPlan.md` — 省電力運用案を追加

### Behavioral Impact
- 画面オフ時のDNS解決が遅延しやすくなる前提を明文化

### Risk & Mitigation
- Risk: 背景通信の遅延で通知/同期が遅れる可能性
- Mitigation: IDLE閾値/遅延の定数を調整可能にする

### Tests / Verification
- 未実施（設計ドキュメント追加のみ）
**2026-01-22 15:36 (Asia/Taipei) — EcoPlanのUTF-8再出力**

### Summary
- doc/EcoPlan.mdをUTF-8（BOMなし）の日本語で再出力

### Context / Goal
- 文字化けを解消し、指定の文字コードで読みやすくする
- 省電力案の文書を正しく参照できる状態にする

### Changes
- doc/EcoPlan.mdの内容をUTF-8（BOMなし）で再書き込み

### Files Touched
- `doc/EcoPlan.md` — UTF-8（BOMなし）で日本語再出力

### Behavioral Impact
- 実行時の挙動変更なし（ドキュメントのみ）

### Risk & Mitigation
- Risk: なし
- Mitigation: なし

### Tests / Verification
- 未実施（ドキュメント再出力のみ）
**2026-01-22 15:41 (Asia/Taipei) — EcoPlan推奨案の実装**

### Summary
- 画面オフ時のアイドル判定と上流解決抑制を導入して省電力化

### Context / Goal
- doc/EcoPlan.mdの推奨案に沿ってVPN継続のまま消費電力を抑える
- watchdog緩和と再起動クールダウンは維持する

### Changes
- 画面ON/OFFの監視とアイドル判定の導入
- アイドル時の上流解決遅延と古いリクエストの抑制
- アイドル遷移のデバッグログを追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — 画面状態監視とアイドル制御を追加

### Behavioral Impact
- 画面オフ中はDNS解決が遅延し、バックグラウンド通信の省電力挙動になる

### Risk & Mitigation
- Risk: 背景通信のDNS遅延で通知/同期に遅れが出る可能性
- Mitigation: IDLE閾値/遅延/破棄閾値は定数で調整可能

### Tests / Verification
- 未実施（実機で画面オン/オフ時の挙動確認が必要）
**2026-01-23 16:07 (Asia/Taipei) — Bugfix5対策の実装**

### Summary
- VPN自身の除外と上流/キュー/自動復旧の安定化を追加

### Context / Goal
- doc/Bugfix5.mdの提案に従い、DNS応答が戻らない停止系の原因を潰す
- 上流の誤ネットワーク束縛やキュー飽和による無応答を減らす

### Changes
- VPN builderで自アプリを除外し、VPN経路への巻き込みを回避
- VPN transportのネットワークを除外して上流ソケットを選別・バインド
- responseQueue満杯時にdrop-oldest+詰まり検知でfatal stop
- 上流resolveの連続失敗を監視してネットワークリセットを自動化

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — VPN除外、上流選別、キュー処理、失敗監視を追加

### Behavioral Impact
- 上流ネットワークの選択が安定し、キュー詰まり時は新しい応答が優先される

### Risk & Mitigation
- Risk: drop-oldestにより古いDNS応答が破棄される
- Mitigation: DNSは鮮度優先のため新しい応答を優先する

### Tests / Verification
- 未実施（実機で切替・長時間稼働の確認が必要）**2026-01-26 13:40 (Asia/Taipei) — 計測メトリクスの追加**

### Summary
- watchdog起床/GC/上流送信の計測ログを追加

### Context / Goal
- doc/measurement-shortest-route.md の計測案を実装し、支配的要因を短時間で把握する
- Energy Profiler / batterystats の外部計測と突き合わせ可能にする

### Changes
- DnsMetrics を追加して watchdog と上流送信のカウンタを集計
- watchdog ループで定期ログを出し、GC差分を取得
- UpstreamResolver で送信/成功/失敗の計測を追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/core/DnsMetrics.kt` — 低負荷の計測カウンタと定期ログを追加
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — watchdog起床計測とレポート呼び出し、上流ワーカーへのメトリクス注入
- `android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt` — 上流送信/成功/失敗のカウントを追加

### Behavioral Impact
- デバッグビルド時に `DnsMetrics` タグで1分間隔の計測ログが出力される

### Risk & Mitigation
- Risk: ログ量と計測オーバーヘッドが増える
- Mitigation: 60秒間隔のサンプリングとデバッグビルド限定で抑制

### Tests / Verification
- 未実施（実機でlogcat出力の確認が必要）
**2026-01-26 14:28 (Asia/Taipei) — P0省電力対応の実装**

### Summary
- watchdog起床を条件化し、上流応答のコピー割り当てを削減

### Context / Goal
- doc/Eco-implementation-priority.md のP0項目を先行実装し、wakeupsとGC負荷を下げる
- 既存の監視/復旧挙動を維持しつつ起床頻度を抑える

### Changes
- responseWatchdogをキュー空時は長間隔待機+通知起床に変更
- enqueueResponseでキュー遷移時にwatchdogを通知
- UpstreamResolverの受信コピーを削減し、length付きで処理
- buildUdpResponseにlength指定版を追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — watchdog待機ロジックと通知起床、上流応答のlength対応
- `android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt` — 応答バッファの再利用とコピー削減
- `android/app/src/main/kotlin/com/example/android_adblocker/core/DnsPacketProcessor.kt` — 応答生成のlength指定版を追加

### Behavioral Impact
- responseQueueが空の間はwatchdog起床が1分間隔に抑制される
- 上流DNS応答の配列コピーが1回減り、GC負荷が低下する

### Risk & Mitigation
- Risk: watchdogの監視間隔延長でstall検知が遅れる可能性
- Mitigation: キュー非空時は従来間隔で監視し、遷移時は通知で即起床
- Risk: 受信バッファ再利用により応答データの取り違えが起きる可能性
- Mitigation: ワーカースレッド単位の専有バッファのみを返す設計に限定

### Tests / Verification
- 未実施（実機でDnsMetricsのwatchdogWakeups/GC低下と通信継続の確認が必要）
**2026-01-26 16:26 (Asia/Taipei) — watchdog待機のビルド修正**

### Summary
- watchdog待機のwait/notify呼び出しをKotlin互換に修正

### Context / Goal
- DnsVpnService.kt のビルドエラーを解消し、P0変更をコンパイル可能にする

### Changes
- responseWatchdogLock の wait/notifyAll を java.lang.Object 経由で呼び出すよう修正

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — wait/notifyAll呼び出しの修正

### Behavioral Impact
- watchdog待機の挙動は維持されたまま、ビルドが通る

### Risk & Mitigation
- Risk: なし（Kotlinの型解決のみの修正）
- Mitigation: 影響箇所をwait/notify呼び出しに限定

### Tests / Verification
- 未実施（Gradle assembleDebugでの確認が必要）
**2026-01-26 17:20 (Asia/Taipei) — watchdog通知の抑制と間隔調整**

### Summary
- watchdog通知を長待機時のみに限定し、アクティブ間隔を延長

### Context / Goal
- アクティブ時のwatchdog起床過多を抑え、アイドル時は通知で即起床させる
- 2秒間隔を5秒に延長できるか検証する

### Changes
- responseWatchdogの待機種別を管理し、長待機中のみnotifyで起床
- アクティブ時のwatchdog待機を5秒に変更

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — watchdog待機状態フラグと間隔定数を追加

### Behavioral Impact
- responseQueueが空のときのみ通知で即起床し、アクティブ時は5秒間隔で監視

### Risk & Mitigation
- Risk: stall検知が最大で5秒遅れる可能性
- Mitigation: 監視は継続し、キュー非空時は定期起床を維持

### Tests / Verification
- 未実施（DnsMetricsでwatchdogWakeupsの減少と通信継続を確認）
**2026-01-26 17:32 (Asia/Taipei) — watchdog通知条件の厳格化**

### Summary
- responseQueueの空→非空遷移時のみwatchdog通知するよう修正

### Context / Goal
- アクティブ時の不要なwatchdog起床を抑え、5秒間隔の監視を維持する
- アイドル時は即起床を維持する

### Changes
- enqueueResponseで通知条件を「キュー空→非空」遷移に限定

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — watchdog通知の条件を厳格化

### Behavioral Impact
- アクティブ時のwatchdog起床が過剰になりにくくなる

### Risk & Mitigation
- Risk: 遷移判定の競合で通知が漏れる可能性
- Mitigation: 長待機中の定期起床（60秒）を維持

### Tests / Verification
- 未実施（DnsMetricsでwatchdogWakeupsの低下を確認）
**2026-01-26 17:41 (Asia/Taipei) — watchdog長待機の条件化**

### Summary
- 長待機への移行を一定アイドル後に限定して通知起床の連打を抑制

### Context / Goal
- 連続アクセス時のwatchdog起床過多を抑え、5秒間隔の監視に寄せる
- アイドル時の即起床は維持する

### Changes
- responseQueue空判定時に直近enqueueからの経過を見て長待機へ切り替え
- enqueue時刻を記録し、停止時にリセット

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — 長待機の条件分岐と時刻管理を追加

### Behavioral Impact
- 連続アクセス中のwatchdog起床が抑制され、アイドル時は長待機で即起床

### Risk & Mitigation
- Risk: 長待機移行が遅れ、アイドル時の省電力効果が弱まる可能性
- Mitigation: 3秒閾値のため移行遅延は最小限

### Tests / Verification
- 未実施（DnsMetricsでwatchdogWakeupsの低下を確認）
**2026-01-26 17:53 (Asia/Taipei) — P1: PowerManager最適化とDNS短期キャッシュ**

### Summary
- PowerManager参照をイベント駆動に寄せ、短期DNSキャッシュを追加

### Context / Goal
- doc/Eco-implementation-priority.md のP1項目を実装し、CPU/ネットワーク負荷を低減する
- 画面状態の判定コスト削減と上流送信回数の削減を狙う

### Changes
- PowerManagerをonCreateで保持し、screenOnフラグでidle判定を行う
- DNS応答の短期キャッシュを追加し、同一問い合わせの上流送信を抑制

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — PowerManagerの保持、screenフラグ化、DNSキャッシュ統合
- `android/app/src/main/kotlin/com/example/android_adblocker/core/DnsPacketProcessor.kt` — qtype/qclassの保持とcacheKey生成
- `android/app/src/main/kotlin/com/example/android_adblocker/core/DnsCache.kt` — TTL付きDNSキャッシュを追加

### Behavioral Impact
- 同一qname/qtype/qclassの短時間再問い合わせは上流送信を回避する
- idle判定時のPowerManager取得コストが削減される

### Risk & Mitigation
- Risk: キャッシュにより古いDNS応答を返す可能性
- Mitigation: TTLを短く（30秒）設定し、容量も限定

### Tests / Verification
- 未実施（DnsMetricsでupstreamSendの低下と挙動確認が必要）
**2026-01-26 18:07 (Asia/Taipei) — DNSキャッシュTTL延長**

### Summary
- DNSキャッシュTTLを30秒から60秒に延長

### Context / Goal
- 上流送信回数のさらなる削減を狙ってキャッシュの効き具合を強める

### Changes
- DNSキャッシュTTLを60秒に変更

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — DNS_CACHE_TTL_MSを延長

### Behavioral Impact
- 同一クエリの上流送信がより抑制される可能性がある

### Risk & Mitigation
- Risk: 応答の鮮度が低下する可能性
- Mitigation: TTLは短めの60秒に留める

### Tests / Verification
- 未実施（再計測が必要）
**2026-01-26 18:20 (Asia/Taipei) — P2: ドメイン判定キャッシュとワーカー削減**

### Summary
- ドメイン判定のLRUキャッシュを追加し、上流ワーカー数を削減

### Context / Goal
- doc/Eco-implementation-priority.md のP2項目を段階的に実装してCPU負荷と待機コストを下げる

### Changes
- DomainRuleMatcherに判定結果のLRUキャッシュを追加
- 上流ワーカー数を6→3へ削減

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/core/DomainRuleMatcher.kt` — 判定結果キャッシュとクリア処理を追加
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — UPSTREAM_WORKER_COUNTを削減

### Behavioral Impact
- 同一ドメイン判定のCPU負荷が低減される
- 上流問い合わせの並列度が下がる

### Risk & Mitigation
- Risk: キャッシュによりメモリ使用が増える
- Mitigation: サイズ上限を4096件に固定
- Risk: ピーク時の上流遅延が増える可能性
- Mitigation: まず3スレッドで観測し必要なら調整可能

### Tests / Verification
- 未実施（DnsMetricsで遅延/送信数の変化を確認）
**2026-01-27 16:46 (Asia/Taipei) — CPU切り分けログ追加**

### Summary
- packetLoopの0バイト読み計測とブロックリスト読み込み時間をログ化し、関連スレッド名を付与

### Context / Goal
- VPN稼働中のCPU 12%張り付きの原因スレッドを最短で特定する

### Changes
- packetLoopで0バイト読みのカウントを1秒間隔でログ出力
- BlocklistLoaderで読み込み開始/完了（件数/経過時間）をログ出力
- packetLoop/responseWriter/responseWatchdog/upstreamWorker/blocklistLoaderのスレッド名を明示

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — 0バイト読みログとスレッド名設定を追加
- `android/app/src/main/kotlin/com/example/android_adblocker/data/BlocklistLoader.kt` — 読み込み開始/完了ログを追加

### Behavioral Impact
- デバッグ時にCPU切り分け用のログが出力され、スレッド名がプロファイラやtopで識別しやすくなる

### Risk & Mitigation
- Risk: 0バイト読みが多い環境でログが増える可能性
- Mitigation: 1秒間隔の集計ログに抑制し、BuildConfig.DEBUG時のみ出力

### Tests / Verification
- 未実施（実機でログ/プロファイラ確認が必要）
**2026-01-27 17:07 (Asia/Taipei) — packetLoop 0バイト読みバックオフ**

### Summary
- 0バイト読みで短いバックオフを入れてbusy loopを抑制

### Context / Goal
- packetLoopが0バイト読みを高速に繰り返しCPUを消費しているため、最短で負荷を下げる

### Changes
- 0バイト読み時に最大20msのスリープを入れるバックオフを追加
- 通常読みが戻った際に0バイトカウントをリセット

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — zero-readバックオフとリセットを追加

### Behavioral Impact
- 0バイト読みが連続する環境でpacketLoopのCPU消費が低下する

### Risk & Mitigation
- Risk: 0バイト読みが頻発する端末でレスポンスがわずかに遅れる可能性
- Mitigation: 最大20msの短いバックオフに制限

### Tests / Verification
- 未実施（CPU使用率とDNS応答遅延の再計測が必要）
**2026-01-27 17:12 (Asia/Taipei) — packetLoopバックオフの撤回**

### Summary
- 0バイト読みバックオフを取り下げて計測のみの状態に戻した

### Context / Goal
- 依頼により直前の修正を差し戻す

### Changes
- 0バイト読み時のスリープとカウントリセットを削除
- 追加した定数を削除

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — zero-readバックオフ関連の変更を撤回

### Behavioral Impact
- 0バイト読みが続く環境では再びbusy loopが起こり得る

### Risk & Mitigation
- Risk: CPU使用率が再上昇する可能性
- Mitigation: ログ計測を継続し、必要なら別案で対処

### Tests / Verification
- 未実施（依頼による差し戻し）
**2026-01-27 17:51 (Asia/Taipei) — poll/select版packetLoop導入**

### Summary
- TUN読み取りをpoll待機へ移行し、wakeup pipeで停止/解除できるようにした

### Context / Goal
- packetLoopのbusy loop由来のCPU張り付き（0バイトread連続）を根治する
- poll待機中でもstopVpnで確実に解除できるようにする

### Changes
- runPacketLoopをpollベースとlegacyベースで分岐（USE_POLL_LOOP）
- WakeupPipeを追加し、stop/fatalでpoll解除
- poll統計ログ（timeouts/wakeups/readZeroAfterReadable）をDEBUGで出力

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — poll loop/WakeupPipe/計測ログを追加

### Behavioral Impact
- idle時のpacketLoop CPU使用率が大幅に低下する見込み
- 停止時にpoll待機が即時解除される

### Risk & Mitigation
- Risk: poll環境依存の挙動でハングやエラーが出る可能性
- Mitigation: pipe作成失敗時はlegacyにフォールバック、USE_POLL_LOOPで切替可能

### Tests / Verification
- 未実施（実機でCPU/停止挙動の確認が必要）
**2026-01-28 10:26 (Asia/Taipei) — 英語UI追加とロケール判定**

### Summary
- 端末言語に応じて日本語/英語UIを切り替え、非日本語は英語にフォールバック

### Context / Goal
- 英語UIを追加し、スマホ言語設定に基づくデフォルト表示を実現する

### Changes
- Flutter UI文字列を英語/日本語で切り替える簡易ローカライズを追加
- MethodChannelエラーメッセージと通知文言をロケールで分岐
- 日本語以外の端末言語は英語へ固定するlocaleResolutionCallbackを設定

### Files Touched
- `lib/main.dart` — UI文言の英語化とロケール判定を追加
- `android/app/src/main/kotlin/com/example/android_adblocker/MainActivity.kt` — エラーメッセージの英日切替を追加
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — 通知文言の英日切替を追加

### Behavioral Impact
- 端末言語が日本語なら日本語、それ以外は英語でUI/通知/一部エラーメッセージが表示される

### Risk & Mitigation
- Risk: ロケール取得タイミングにより初回表示が想定外になる可能性
- Mitigation: Flutter側はプラットフォームロケールにフォールバックし、Android側も直接ロケール参照

### Tests / Verification
- 未実施（英語/日本語ロケールでの表示確認が必要）
**2026-01-28 10:31 (Asia/Taipei) — main.dart日本語の文字化け修正**

### Summary
- lib/main.dartの日本語文字列をUTF-8で再書き込み

### Context / Goal
- 日本語が??に文字化けしていたため、UTF-8で正しい文字列に戻す

### Changes
- UI文言/コメントの日本語テキストをUTF-8で再保存

### Files Touched
- `lib/main.dart` — 日本語テキストの文字化けを修正

### Behavioral Impact
- 日本語表示が正しく復元される

### Risk & Mitigation
- Risk: 文字列差し替えに伴う意図しないUI変更
- Mitigation: 既存文言を維持して再書き込みのみ実施

### Tests / Verification
- 未実施（表示確認が必要）
**2026-01-28 14:41 (Asia/Taipei) — main.dart文字化け再修正**

### Summary
- lib/main.dartの日本語をUTF-8で再書き込みして復元

### Context / Goal
- 日本語が??になっていたため正しい文字列へ戻す

### Changes
- UI文言とコメントの日本語テキストをUTF-8で再保存

### Files Touched
- `lib/main.dart` — 日本語文字列を復元

### Behavioral Impact
- 日本語UI表示が正しくなる

### Risk & Mitigation
- Risk: 文字列再書き込みによる意図しない差分
- Mitigation: 文言内容は既存と同一に維持

### Tests / Verification
- 未実施（表示確認が必要）
**2026-01-30 11:40 (Asia/Taipei) — VPN再確立エスカレーション実装**

### Summary
- Upstream再接続を維持しつつ、需要+安定条件を満たした場合のみVPN再確立に昇格する仕組みを追加

### Context / Goal
- reset連発やTUN無通信が回復しない場合にのみStop/Startで復旧させ、暴発を抑制したい
- validated単体に依存せず、需要/ネットワーク安定性も判断材料に含めたい

### Changes
- DNS需要シグナル（lastDnsQueryAtMs/dnsQueryCount）とエスカレーション判定を追加
- reset/ネットワーク変化中のStop/Start競合を避けるため再起動中のreset抑止を導入
- 診断ログにエスカレーション関連の指標を追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — VPN再確立の昇格条件、需要シグナル、再起動オーケストレーション、診断ログ拡張を追加

### Behavioral Impact
- 需要があり、かつ安定したネットワーク上でresetが連続する場合のみVPNインタフェースを再確立する
- 再起動中はresetを抑止し、診断ログで理由と状態を追跡できる

### Risk & Mitigation
- Risk: エスカレーション条件が厳しすぎて復旧が遅れる可能性
- Mitigation: 需要/安定性/連続失敗の複合条件をログで可視化し、閾値は定数で調整可能にしている

### Tests / Verification
- 未実施（動作確認とログ検証が必要）

## 2026-01-30 14:15 (Asia/Taipei) — ネットワーク監視の全回線化と上流ログ強化

### Summary
- VPN以外の回線監視とvalidated判定を強化し、上流失敗ログを追加

### Context / Goal
- エレベーター復帰後の通信不能対策として監視範囲と再評価を安定化する
- 失敗時の原因追跡を容易にする

### Changes
- registerNetworkCallbackを全APIで使用し、INTERNET+NOT_VPNで監視
- validated状態を比較キーに加え、回線再評価ログを分離
- 上流DNS解決失敗時に例外種別/メッセージをDEBUGで出力

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — 監視範囲の拡張、validated比較、再評価ログ
- `android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt` — 失敗時ログの追加
- `.agent/changes.md` — 変更記録を追記

### Behavioral Impact
- VPN以外の回線変化に対してresetがより正確に走り、validated変化も反映される
- 上流障害時のログに原因が残る

### Risk & Mitigation
- Risk: onCapabilitiesChangedの通知増加による不要なreset
- Mitigation: NOT_VPNフィルタとvalidated比較でノイズを抑制

### Tests / Verification
- 未実施（Wi-Fi/LTE切替とlogcat確認が必要）
**2026-02-02 10:47 (Asia/Taipei) — Upstream失敗率+成功なし時間でのreset追加**

### Summary
- Upstreamの成功なし時間と失敗率でresetを判断する復旧ロジックを追加

### Context / Goal
- 短時間断でNetworkCallbackが来ない場合でも自己回復できるようにしたい
- たまの成功で連続失敗がリセットされ、復旧が発火しない問題を避けたい

### Changes
- Upstream結果のウィンドウ集計（成功なし時間・失敗率）とcooldownを導入
- 上流解決ごとに結果を記録し、条件一致時にresetを実行

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — 成功なし時間/失敗率の判定とresetトリガ、状態初期化を追加

### Behavioral Impact
- NetworkCallbackが来ない瞬断でも、成功なし時間と失敗率が高い場合にresetが発火する
- resetの連打はcooldownで抑制される

### Risk & Mitigation
- Risk: 失敗率判定が過敏でresetが増える可能性
- Mitigation: 最小サンプル数とcooldownを設け、閾値は定数で調整可能にしている

### Tests / Verification
- 未実施（エレベーター状況でのログ確認が必要）
**2026-02-02 13:33 (Asia/Taipei) — RCODEログとDIAGスナップショット追加**

### Summary
- DNS応答コード(RCODE)のログとDIAGスナップショット出力を追加

### Context / Goal
- 一部サイトのみ遅延/失敗する原因切り分けのため、DNS応答内容と状態を可視化したい

### Changes
- 応答種別（blocked/servfail/cache/upstream）のRCODEをDEBUGで出力
- ACTION_DIAG で状態サマリを出すログ関数を追加
- Upstreamウィンドウ集計をDIAGに表示

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/core/DnsPacketProcessor.kt` — Immediate結果にquery/rcodeを付与
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — RCODEログ、DIAGログ、ACTION_DIAG追加

### Behavioral Impact
- DEBUG時にDNS応答のRCODEと診断スナップショットがログへ出力される

### Risk & Mitigation
- Risk: ログ量増加によるノイズ
- Mitigation: DEBUG_LOGS条件でのみ出力

### Tests / Verification
- 未実施（ログ出力の確認が必要）
**2026-02-02 13:53 (Asia/Taipei) — Fad-success提案の安全性補強**

### Summary
- Fad-success.mdの修正案を副作用が少ない形に調整

### Context / Goal
- 0ms近い偽成功で復旧判定が潰れないようにしたい
- 端末差による誤判定を避けたい

### Changes
- 偽成功は「失敗扱い」ではなく「lastUpstreamSuccessAtMs更新抑制」に変更
- 閾値は2msではなく5msを推奨と明記
- DNS ID/Question一致の代替案も追記

### Files Touched
- `doc/Fad-success.md` — 偽成功フィルタの安全な実装方針を記載

### Behavioral Impact
- 文書更新のみ（挙動変更なし）

### Risk & Mitigation
- Risk: 文章変更による誤解
- Mitigation: 具体例と理由を明記

### Tests / Verification
- 未実施（文書変更のみ）
**2026-02-02 13:57 (Asia/Taipei) — 偽の成功フィルタ導入**

### Summary
- Upstream応答が極端に短い場合は成功時刻を更新しないように調整

### Context / Goal
- 0ms近い偽成功で復旧判定が潰れないようにしたい
- 成功扱いを維持しつつ、noSuccess判定を保ちたい

### Changes
- Upstreamの応答時間を計測し、5ms未満の成功はlastUpstreamSuccessAtMsを更新しない
- 判定用定数を追加

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — Upstream成功のフィルタリングと定数追加

### Behavioral Impact
- 極端に短い成功がnoSuccess判定をリセットしなくなる

### Risk & Mitigation
- Risk: 低遅延環境で正当な成功を見逃す可能性
- Mitigation: 閾値は5msと低めで、失敗扱いにはせず更新抑制のみに留めた

### Tests / Verification
- 未実施（ログ/体感での確認が必要）

2026-02-03 11:45 (Asia/Taipei) — Add debug logging for network reset diagnosis

### Summary
- add detailed network/capability/reset and upstream failure logs to confirm reset behavior

### Context / Goal
- capture evidence for same-Network state changes and reset decisions during radio outages
- make upstream failure context observable

### Changes
- add NET_* logging and link/capability handling in DnsVpnService
- log upstream failure details and counters
- update debug log plan with message prefixes

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — add network/capability/reset logs and link properties handling
- ndroid/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt — add upstream failure log details
- doc/DebugLogPlan.md — update plan with log prefixes and examples

### Behavioral Impact
- network link/capability changes on same Network now trigger reset scheduling
- additional debug logging emitted in debug builds

### Risk & Mitigation
- Risk: extra reset triggers may add overhead on noisy networks
- Mitigation: logging is debug-only; reset scheduling already de-duped via idle logic

### Tests / Verification
- not run (log instrumentation only)

2026-02-03 13:09 (Asia/Taipei) — Add non-VPN NetworkCallback implementation plan

### Summary
- document a plan to register a non-VPN network callback and related debug logging

### Context / Goal
- ensure upstream network changes are visible even when default callback is bound to VPN

### Changes
- add doc/NonVpnNetworkCallbackPlan.md with implementation details and fallback logging

### Files Touched
- doc/NonVpnNetworkCallbackPlan.md — non-VPN callback plan and debug log guidance

### Behavioral Impact
- none (documentation only)

### Risk & Mitigation
- Risk: plan drift if code changes diverge
- Mitigation: follow plan and keep log prefixes consistent

### Tests / Verification
- not run (documentation only)

2026-02-03 13:10 (Asia/Taipei) — Translate NonVpnNetworkCallbackPlan to Japanese

### Summary
- rewrite doc/NonVpnNetworkCallbackPlan.md in Japanese

### Context / Goal
- provide Japanese implementation plan for non-VPN callback

### Changes
- update content to Japanese while keeping technical details

### Files Touched
- doc/NonVpnNetworkCallbackPlan.md — Japanese version

### Behavioral Impact
- none (documentation only)

### Risk & Mitigation
- Risk: none
- Mitigation: none

### Tests / Verification
- not run (documentation only)

2026-02-03 13:16 (Asia/Taipei) — Add non-VPN NetworkCallback monitoring

### Summary
- register non-VPN NetworkCallback to observe cellular/wifi/ethernet changes

### Context / Goal
- ensure upstream network state changes are visible even when default callback binds to VPN

### Changes
- add non-VPN NetworkRequest and callback with NET_MON_NONVPN logs
- unregister non-VPN callback during stopNetworkMonitor
- track nonVpnCallback field

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — add non-VPN monitoring

### Behavioral Impact
- non-VPN network changes now trigger updateCurrentNetwork and potential reset

### Risk & Mitigation
- Risk: extra callbacks increase log volume in debug builds
- Mitigation: logs are guarded by DEBUG_LOGS

### Tests / Verification
- not run (instrumentation change only)

2026-02-03 13:22 (Asia/Taipei) — Fix notification string literal

### Summary
- fix malformed NotificationCompat.Builder setContentText string

### Context / Goal
- resolve Kotlin compilation errors from broken string literal

### Changes
- replace corrupted text with ASCII string to restore valid syntax

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — fix setContentText string

### Behavioral Impact
- notification text now reads "DNS filter active"

### Risk & Mitigation
- Risk: none
- Mitigation: n/a

### Tests / Verification
- not run (compile fix only)

2026-02-03 13:46 (Asia/Taipei) — Add High fix plan for non-VPN reset

### Summary
- document a high-priority fix plan to trigger reset on same-network changes in non-VPN callback

### Context / Goal
- avoid missing validated/link changes when updateCurrentNetwork returns same network

### Changes
- add doc/HighFixPlan_NonVpnReset.md with implementation outline

### Files Touched
- doc/HighFixPlan_NonVpnReset.md — plan for non-VPN same-network reset

### Behavioral Impact
- none (documentation only)

### Risk & Mitigation
- Risk: none
- Mitigation: none

### Tests / Verification
- not run (documentation only)
2026-02-03 13:51 (Asia/Taipei) — Implement non-VPN same-network reset handling

### Summary
- trigger reset when non-VPN callbacks detect validated/link changes on current network

### Context / Goal
- avoid missing same-network state changes when updateCurrentNetwork returns early

### Changes
- add validated flip handling in non-VPN onCapabilitiesChanged
- add same-network reset in non-VPN onLinkPropertiesChanged

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — non-VPN callback reset logic

### Behavioral Impact
- same-network validated/link changes now trigger reset from non-VPN callback

### Risk & Mitigation
- Risk: increased reset frequency on noisy networks
- Mitigation: reset only on validated flip or link change

### Tests / Verification
- not run (logic change only)
2026-02-03 13:55 (Asia/Taipei) — Restore non-VPN same-network reset logic

### Summary
- reapply reset handling for non-VPN same-network capability/link changes

### Context / Goal
- ensure same-network validated/link changes trigger reset after accidental edits

### Changes
- re-add validated flip handling and reset in non-VPN onCapabilitiesChanged
- re-add same-network reset in non-VPN onLinkPropertiesChanged

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — non-VPN callback reset logic

### Behavioral Impact
- same-network validated/link changes now trigger reset from non-VPN callback

### Risk & Mitigation
- Risk: increased reset frequency on noisy networks
- Mitigation: reset only on validated flip or link change

### Tests / Verification
- not run (logic change only)
2026-02-04 09:55 (Asia/Taipei) — Add plan for DNS block/rcode logging

### Summary
- document plan to log block decisions and DNS response rcode

### Context / Goal
- identify blocked domains and NXDOMAIN/SERVFAIL responses when sites fail to load

### Changes
- add doc/DnsBlockAndRcodeLogPlan.md with implementation outline

### Files Touched
- doc/DnsBlockAndRcodeLogPlan.md — block/rcode logging plan

### Behavioral Impact
- none (documentation only)

### Risk & Mitigation
- Risk: none
- Mitigation: none

### Tests / Verification
- 未実施（ドキュメントのみ）
2026-02-04 10:04 (Asia/Taipei) — Add RCODE/DIAG log plan

### Summary
- document plan for DNS RCODE logging and DIAG snapshot logging

### Context / Goal
- improve DNS response visibility and diagnostic context for troubleshooting

### Changes
- add doc/RcodeDiagLogPlan.md with implementation proposal

### Files Touched
- doc/RcodeDiagLogPlan.md — RCODE/DIAG logging plan

### Behavioral Impact
- none (documentation only)

### Risk & Mitigation
- Risk: none
- Mitigation: none

### Tests / Verification
- 未実施（ドキュメントのみ）
2026-02-04 10:11 (Asia/Taipei) — Add DNS RCODE and DIAG logging

### Summary
- add RCODE logging for DNS responses and DIAG snapshots for upstream health

### Context / Goal
- improve visibility into DNS response codes and upstream failure patterns during connectivity issues
- enable manual diagnostics via ACTION_DIAG

### Changes
- log DNS block decisions and response RCODEs in DnsPacketProcessor
- log DIAG snapshots and upstream window stats in DnsVpnService
- emit RCODE logs for servfail and upstream responses

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/core/DnsPacketProcessor.kt — add DNS_RCODE logging helpers and block logging
- ndroid/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt — add DIAG snapshot logging and RCODE hooks

### Behavioral Impact
- debug builds now emit DNS_RCODE and DIAG logs; runtime behavior unchanged

### Risk & Mitigation
- Risk: debug log volume increases
- Mitigation: logs are guarded by DEBUG_LOGS and fail snapshots are throttled by threshold

### Tests / Verification
- 未実施（ログ追加のみ）
2026-02-04 10:19 (Asia/Taipei) — Fix DnsPacketProcessor companion visibility

### Summary
- expose companion object so DnsVpnService can access DNS_RCODE_SERVFAIL

### Context / Goal
- resolve build failure due to private companion access from DnsVpnService

### Changes
- remove private visibility from DnsPacketProcessor companion object

### Files Touched
- ndroid/app/src/main/kotlin/com/example/android_adblocker/core/DnsPacketProcessor.kt — make companion object accessible

### Behavioral Impact
- no runtime behavior change; compile error resolved

### Risk & Mitigation
- Risk: internal constants become accessible within module
- Mitigation: class is internal; exposure limited to module scope

### Tests / Verification
- 未実施（ビルドエラー修正のみ）
2026-02-04 10:25 (Asia/Taipei) — Add debug DIAG broadcast receiver

### Summary
- add debug-only BroadcastReceiver to trigger ACTION_DIAG without exporting the VPN service

### Context / Goal
- allow adb broadcast to trigger DIAG logging while keeping DnsVpnService unexported

### Changes
- register debug-only receiver for com.example.android_adblocker.action.DIAG
- implement DiagReceiver to forward action to DnsVpnService

### Files Touched
- ndroid/app/src/debug/AndroidManifest.xml — add DIAG receiver intent-filter
- ndroid/app/src/debug/kotlin/com/example/android_adblocker/debug/DiagReceiver.kt — handle DIAG broadcast and start service

### Behavioral Impact
- debug builds accept DIAG broadcast and log diagnostics; release builds unchanged

### Risk & Mitigation
- Risk: debug receiver is exported and could be triggered by other apps in debug builds
- Mitigation: receiver exists only in debug source set

### Tests / Verification
- 未実施（ログ用のデバッグ機構追加のみ）

2026-03-31 11:21 (Asia/Taipei) — Harden upstream DNS failover and stale response handling

### Summary
- prevent delayed upstream DNS replies from being misrouted and add secondary upstream fallback

### Context / Goal
- Android VPN service could accept a delayed DNS reply for the wrong later query on poor networks
- single-upstream UDP resolution made timeouts turn into immediate SERVFAIL without another path

### Changes
- rewrote `UpstreamResolver` to connect sockets per endpoint, validate DNS ID and question, and discard stale replies within a per-query deadline
- added primary/secondary upstream endpoint failover and updated worker handling to consume structured resolve results

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt` — add endpoint model, failover flow, deadline slicing, response validation, and diagnostic logging
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — switch workers to multi-endpoint resolver and log which upstream served successful responses

### Behavioral Impact
- delayed DNS responses that do not match the active query are discarded instead of being returned to another request
- upstream resolution now retries against a secondary resolver before falling back to SERVFAIL

### Risk & Mitigation
- Risk: splitting the timeout budget across two upstreams may slightly increase failure sensitivity for the primary path
- Mitigation: the resolver uses the full remaining budget on the last endpoint and logs failover/final failure for tuning

### Tests / Verification
- `android\\gradlew.bat app:compileDebugKotlin`

2026-03-31 13:11 (Asia/Taipei) — Add missing blocklist domains from public list comparison

### Summary
- add four recommended domains that were absent from the current runtime blocklist

### Context / Goal
- current Android blocklist already covered most recommended ad-tech roots, but a few useful domains were still missing
- add only domains with comparatively low overblocking risk or narrowly scoped tracking subdomains

### Changes
- appended `tapad.com` and `scorecardresearch.com` as missing ad-tech / measurement roots
- appended `an.facebook.com` and `log.byteoversea.com` as narrower telemetry domains instead of blocking broader parent domains

### Files Touched
- `android/app/src/main/assets/blocklist.txt` — append four manually curated domains with a manual-additions comment block

### Behavioral Impact
- requests to the added domains and their subdomains will now be blocked by the suffix matcher
- Facebook and ByteDance coverage is intentionally limited to specific telemetry subdomains to reduce breakage risk

### Risk & Mitigation
- Risk: `scorecardresearch.com` or the telemetry subdomains may still affect analytics or ad attribution in some apps
- Mitigation: additions were kept narrow, and broad roots like `facebook.com` / `tiktok.com` were intentionally not added

### Tests / Verification
- verified each added domain appears exactly once in `android/app/src/main/assets/blocklist.txt`

2026-04-04 00:42 (Asia/Taipei) — Fix upstream response validation and failover worker crash

### Summary
- relax upstream DNS response validation to semantic question matching and fix failover send crash on connected UDP sockets

### Context / Goal
- raw-byte question matching could discard valid DNS replies when question encoding differed despite matching semantics
- failover reproduced a process crash with `IllegalArgumentException: connected address and packet address differ` from `upstreamWorker#3`

### Changes
- updated `UpstreamResolver` to validate replies by DNS ID plus normalized `QNAME/QTYPE/QCLASS`, including compressed-name parsing and finer mismatch reasons
- aligned the reusable request `DatagramPacket` destination with the currently connected endpoint before send and handled `IllegalArgumentException` as an upstream failure
- wrapped upstream worker query handling so unexpected throwables are logged, converted to `SERVFAIL`, and trigger reset recovery instead of crashing the process
- documented the response-validation fix approach in `doc/UpstreamResponseValidationFixPlan.md`

### Files Touched
- `android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt` — replace raw question-byte comparison with semantic parsing, support name compression, and fix failover packet destination handling
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt` — pass structured DNS query fields into the resolver and guard upstream workers from uncaught runtime exceptions
- `doc/UpstreamResponseValidationFixPlan.md` — record the investigation, root cause hypothesis, and planned validation strategy

### Behavioral Impact
- valid upstream replies with equivalent question semantics are no longer discarded solely because their question bytes differ from the original query
- failover between upstream endpoints no longer crashes the app when a connected socket reuses a packet that still points at the previous endpoint
- unexpected upstream worker exceptions now degrade to logged `SERVFAIL` responses and reset recovery instead of terminating the app process

### Risk & Mitigation
- Risk: the new compressed-name parser could still reject malformed edge cases or accept cases that need tighter validation
- Mitigation: pointer chasing is bounded, packet bounds are checked, mismatch reasons remain explicit, and build verification was rerun after the change

### Tests / Verification
- `android\\gradlew.bat app:compileDebugKotlin` with `JAVA_HOME=C:\\Program Files\\Microsoft\\jdk-17.0.17.10-hotspot`
- reproduced-crash log review confirmed the original fatal path was `DatagramSocket.send()` during failover on `upstreamWorker#3`
