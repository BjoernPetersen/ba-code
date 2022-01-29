import 'package:cryptography/cryptography.dart';
import 'package:opaque/src/model/client.dart';

const usernameHeader = 'X-OPAQUE-USER';

class SessionSecurity {
  final AesGcm _aes;
  late final Future<SecretKey> _key;

  SessionSecurity(Bytes key) : _aes = AesGcm.with256bits() {
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
