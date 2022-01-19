import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

class SessionManager {
  final Map<String, SessionSecurity> _sessions = {};

  void setSession(String username, SessionSecurity session) {
    _sessions[username] = session;
  }

  SessionSecurity? getSession(String username) {
    return _sessions[username];
  }
}

class SessionSecurity {
  final AesGcm _aes;
  late final Future<SecretKey> _key;

  SessionSecurity(Uint8List key) : _aes = AesGcm.with256bits() {
    _key = _aes.newSecretKeyFromBytes(key);
  }

  Future<List<int>> encrypt(List<int> data) async {
    final encrypted = await _aes.encrypt(data, secretKey: await _key);
    return encrypted.concatenation();
  }

  Future<List<int>> decrypt(List<int> payload) async {
    final box = SecretBox.fromConcatenation(
      payload,
      nonceLength: 12,
      macLength: AesGcm.aesGcmMac.macLength,
    );
    return await _aes.decrypt(box, secretKey: await _key);
  }
}
