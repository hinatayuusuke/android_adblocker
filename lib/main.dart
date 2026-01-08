import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// 目的: アプリのエントリーポイントとしてUIを起動する。
/// 引数: なし。
/// 戻り値: なし。
/// 副作用: Flutterのレンダリングを開始する。
void main() {
  runApp(const _AdBlockerApp());
}

bool get _isAndroid => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

class _AdBlockerApp extends StatelessWidget {
  const _AdBlockerApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DNS AdBlocker',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1E3A5F),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF6F3EE),
        useMaterial3: true,
      ),
      home: const _HomeScreen(),
    );
  }
}

class _HomeScreen extends StatefulWidget {
  const _HomeScreen();

  @override
  State<_HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<_HomeScreen> {
  final _platform = _VpnPlatform();
  final _domainController = TextEditingController();
  bool _isRunning = false;
  bool _isBusy = false;
  String? _errorMessage;
  List<String> _allowlist = const [];

  @override
  void initState() {
    super.initState();
    _refreshState();
  }

  @override
  void dispose() {
    _domainController.dispose();
    super.dispose();
  }

  Future<void> _refreshState() async {
    if (!_isAndroid) {
      setState(() {
        _errorMessage = 'Android専用の機能です。';
      });
      return;
    }
    final running = await _platform.isRunning();
    final allowlist = await _platform.getAllowlist();
    setState(() {
      _isRunning = running;
      _allowlist = allowlist..sort();
    });
  }

  Future<void> _toggleVpn() async {
    if (_isBusy) return;
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      if (_isRunning) {
        await _platform.stop();
      } else {
        final prepared = await _platform.prepare();
        if (!prepared) {
          setState(() {
            _errorMessage = 'VPNの許可が必要です。';
          });
          return;
        }
        await _platform.start();
      }
      await _refreshState();
    } on PlatformException catch (error) {
      setState(() {
        _errorMessage = error.message ?? '操作に失敗しました。';
      });
    } finally {
      if (mounted) {
        setState(() {
          _isBusy = false;
        });
      }
    }
  }

  Future<void> _addAllowlist() async {
    final text = _domainController.text.trim().toLowerCase();
    if (text.isEmpty) return;
    if (_allowlist.contains(text)) {
      _domainController.clear();
      return;
    }
    final updated = [..._allowlist, text]..sort();
    await _platform.setAllowlist(updated);
    setState(() {
      _allowlist = updated;
      _domainController.clear();
    });
  }

  Future<void> _removeAllowlist(String domain) async {
    final updated = _allowlist.where((item) => item != domain).toList();
    await _platform.setAllowlist(updated);
    setState(() {
      _allowlist = updated;
    });
  }

  @override
  Widget build(BuildContext context) {
    final statusText = _isRunning ? '稼働中' : '停止中';
    final statusColor = _isRunning ? const Color(0xFF136F63) : const Color(0xFF8A1C1C);
    return Scaffold(
      appBar: AppBar(
        title: const Text('DNS AdBlocker'),
        backgroundColor: const Color(0xFF1E3A5F),
        foregroundColor: Colors.white,
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(18),
                boxShadow: const [
                  BoxShadow(
                    blurRadius: 12,
                    color: Color(0x1A000000),
                    offset: Offset(0, 6),
                  ),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('VPNステータス', style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Container(
                        width: 12,
                        height: 12,
                        decoration: BoxDecoration(
                          color: statusColor,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(statusText, style: TextStyle(color: statusColor)),
                      const Spacer(),
                      FilledButton(
                        onPressed: _isBusy ? null : _toggleVpn,
                        child: Text(_isRunning ? '停止' : '開始'),
                      ),
                    ],
                  ),
                  if (_errorMessage != null) ...[
                    const SizedBox(height: 12),
                    Text(
                      _errorMessage!,
                      style: const TextStyle(color: Color(0xFF8A1C1C)),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFFFDF7ED),
                borderRadius: BorderRadius.circular(18),
                border: Border.all(color: const Color(0xFFE6D9C8)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('許可リスト', style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 8),
                  const Text('ここに登録したドメインは常に許可されます。'),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _domainController,
                          decoration: const InputDecoration(
                            labelText: '例: example.com',
                            border: OutlineInputBorder(),
                          ),
                          onSubmitted: (_) => _addAllowlist(),
                        ),
                      ),
                      const SizedBox(width: 12),
                      FilledButton(
                        onPressed: _addAllowlist,
                        child: const Text('追加'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  if (_allowlist.isEmpty)
                    const Text('登録されたドメインはありません。')
                  else
                    for (final domain in _allowlist)
                      ListTile(
                        contentPadding: EdgeInsets.zero,
                        title: Text(domain),
                        trailing: IconButton(
                          icon: const Icon(Icons.close),
                          onPressed: () => _removeAllowlist(domain),
                        ),
                      ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _VpnPlatform {
  static const MethodChannel _channel = MethodChannel('adblocker_vpn');

  Future<bool> prepare() async {
    if (!_isAndroid) {
      return false;
    }
    final result = await _channel.invokeMethod<bool>('prepareVpn');
    return result ?? false;
  }

  Future<void> start() async {
    if (!_isAndroid) return;
    await _channel.invokeMethod('startVpn');
  }

  Future<void> stop() async {
    if (!_isAndroid) return;
    await _channel.invokeMethod('stopVpn');
  }

  Future<bool> isRunning() async {
    if (!_isAndroid) return false;
    final result = await _channel.invokeMethod<bool>('isRunning');
    return result ?? false;
  }

  Future<List<String>> getAllowlist() async {
    if (!_isAndroid) return const [];
    final result = await _channel.invokeMethod<List<Object?>>('getAllowlist');
    if (result == null) return const [];
    return result.whereType<String>().toList();
  }

  Future<void> setAllowlist(List<String> domains) async {
    if (!_isAndroid) return;
    await _channel.invokeMethod('setAllowlist', {'domains': domains});
  }
}
