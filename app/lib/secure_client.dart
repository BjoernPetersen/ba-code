import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:opaque/client.dart';

abstract class SecureClient {
  factory SecureClient({
    required String clientIdentity,
    required String serverDomain,
    required Bytes sessionKey,
  }) = _SecureClientImpl;

  Future<List<int>> get({required String path});
}

class _SecureClientImpl implements SecureClient {
  final String _clientIdentity;
  final String _serverDomain;
  final SessionSecurity _sessionSecurity;

  _SecureClientImpl({
    required String clientIdentity,
    required String serverDomain,
    required Bytes sessionKey,
  })  : _clientIdentity = clientIdentity,
        _serverDomain = serverDomain,
        _sessionSecurity = SessionSecurity(sessionKey);

  @override
  Future<List<int>> get({
    required String path,
  }) async {
    final url = Uri.https(_serverDomain, path);
    final rawResponse = await http.get(
      url,
      headers: {usernameHeader: _clientIdentity},
    );
    if (rawResponse.statusCode >= 400) {
      throw HttpException(
        'Got unsuccessful status code ${rawResponse.statusCode}',
        uri: url,
      );
    }
    return await _sessionSecurity.decrypt(rawResponse.bodyBytes);
  }
}
