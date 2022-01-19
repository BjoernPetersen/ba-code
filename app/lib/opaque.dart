import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:opaque/client.dart';

class OpaqueHandler {
  static const _encoder = AsciiEncoder();

  final Opaque _opaque;
  Bytes? _sessionKey;

  OpaqueHandler() : _opaque = Opaque(Suite.sha256p256());

  bool get isLoggedIn => _sessionKey != null;

  Future<bool> register({
    required String username,
    required String password,
  }) async {
    final passwordBytes = _encoder.convert(password);
    final registration = _opaque.offlineRegistration;
    final initResult = await registration.createRegistrationRequest(
      password: passwordBytes,
    );
    final remoteClient = _RemoteClient();
    final Bytes responseBytes;
    try {
      responseBytes = await remoteClient.post(
        path: '/opaque/$username/registration/init',
        body: initResult.request.serialize(),
      );
    } on _HttpException catch (e) {
      if (kDebugMode) {
        print('Encountered HTTP error $e');
      }
      return false;
    }
    final response = RegistrationResponse.fromBytes(
      _opaque.suite.constants,
      responseBytes,
    );
    final finalizeResult = await registration.finalizeRequest(
      password: passwordBytes,
      blind: initResult.blind,
      response: response,
      serverIdentity: _encoder.convert('opaque.bjoernpetersen.net'),
      clientIdentity: _encoder.convert(username),
    );
    try {
      await remoteClient.post(
        path: '/opaque/$username/registration/finalize',
        body: finalizeResult.record.serialize(),
      );
    } on _HttpException catch (e) {
      if (kDebugMode) {
        print('Encountered HTTP error $e');
      }
      return false;
    }

    return true;
  }

  Future<bool> login({
    required String username,
    required String password,
  }) async {
    // TODO implement
    throw UnimplementedError();
  }
}

class _HttpException implements Exception {
  final int code;
  final String text;

  _HttpException({
    required this.code,
    required this.text,
  });

  @override
  String toString() {
    return 'HTTP error $code: $text';
  }
}

class _RemoteClient {
  static Uri baseUrl = Uri.https('opaque.bjoernpetersen.net', '');

  Future<Bytes> post({
    required String path,
    required Bytes body,
  }) async {
    final uri = baseUrl.resolve(path);
    final response = await http.post(uri, body: body);
    if (response.statusCode >= 400) {
      final body = response.body;
      throw _HttpException(code: response.statusCode, text: body);
    }
    return response.bodyBytes;
  }
}
