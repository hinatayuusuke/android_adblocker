# Project Structure (high-level)
- `lib/main.dart`: Flutter UI and MethodChannel integration.
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt`: DNS-only VPN service, packet loop, network monitor.
- `android/app/src/main/kotlin/com/example/android_adblocker/net/UpstreamResolver.kt`: Upstream DNS resolver.
- `android/app/src/main/kotlin/com/example/android_adblocker/core/*`: DNS parsing, caching, metrics, rule matching.
- `doc/`: investigation reports and logging design notes.
