# Android AdBlocker (DNS-only VPN)

Android AdBlocker is a Flutter-based Android app that blocks ads and trackers at the DNS level using a local `VpnService`. It routes only DNS traffic through a TUN interface, evaluates domains against a blocklist/allowlist, and returns a filtered response without proxying full app traffic.

## Features
- DNS-only VPN (no full traffic tunneling)
- Blocklist and allowlist support
- Local processing by default
- Foreground service with Android 14+ compatibility
- Simple Flutter UI to start/stop and manage allowlist

## Limitations
- DNS-only blocking cannot filter HTTPS paths (e.g., `/ads/...`).
- Apps that use hardcoded IPs bypass DNS filtering.
- Android Private DNS (DoT) can reduce effectiveness if the OS bypasses the local DNS.
- TCP/53 and IPv6 are not fully covered in the current MVP.

## Project Structure
- `lib/main.dart`  EFlutter UI and MethodChannel integration
- `android/app/src/main/kotlin/com/example/android_adblocker/service/DnsVpnService.kt`  EDNS-only VPN service
- `android/app/src/main/kotlin/com/example/android_adblocker/MainActivity.kt`  EMethodChannel bridge and VPN permission flow
- `android/app/src/main/assets/blocklist.txt`  ESample blocklist

## Requirements
- Flutter SDK (Dart 3.10+)
- Android SDK 34+ recommended (FGS rules apply on Android 14+)

## Setup
1. Install Flutter and Android SDK.
2. Run `flutter pub get`.
3. Build or run on an Android device:
   - `flutter run`

## Usage
1. Launch the app.
2. Tap **Start** to request VPN permission and enable DNS filtering.
3. Add domains to the allowlist to always permit them.

## Privacy
The DNS filter runs locally on the device. DNS queries that are not blocked are forwarded to the upstream resolver (default: `1.1.1.1`). No telemetry or analytics are included.

## License
MIT. See `LICENSE`.

