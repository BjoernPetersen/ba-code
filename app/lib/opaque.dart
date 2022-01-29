import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:opaque/client.dart';
import 'package:opaque_app/secure_client.dart';
import 'package:opaque_app/state.dart';

class OpaqueHandler {
  static const _encoder = AsciiEncoder();

  final Opaque _opaque;
  String? _username;

  // TODO: don't hardcode this?
  final String serverDomain = 'opaque.bjoernpetersen.net';
  Bytes? _sessionKey;

  OpaqueHandler()
      : _opaque = Opaque(Suite.sha256p256(
          mhf: MemoryHardFunction.scrypt(),
        ));

  bool get isLoggedIn => _sessionKey != null;

  String get username {
    final username = _username;
    if (username == null) {
      throw StateError('Not logged in');
    }
    return username;
  }

  SecureClient get secureClient {
    final sessionKey = _sessionKey;
    if (sessionKey == null) {
      throw StateError('Not logged in');
    }

    return SecureClient(
      sessionKey: sessionKey,
      serverDomain: serverDomain,
      clientIdentity: _username!,
    );
  }

  Future<bool> register({
    required String username,
    required String password,
  }) async {
    final passwordBytes = _encoder.convert(password);
    final registration = _opaque.offlineRegistration;
    final initResult = await registration.createRegistrationRequest(
      password: passwordBytes,
    );
    final remoteClient = _RemoteClient(domain: serverDomain);
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
      serverIdentity: _encoder.convert(serverDomain),
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
    final state = MemoryClientState();
    final ake = _opaque.getOnlineAke(state);
    final ke1 = await ake.init(
      password: _encoder.convert(password),
    );
    final remoteClient = _RemoteClient(domain: serverDomain);

    final Bytes responseBytes;
    try {
      responseBytes = await remoteClient.post(
        path: '/opaque/$username/login/init',
        body: ke1.serialize(),
      );
    } on _HttpException catch (e) {
      if (kDebugMode) {
        print('Encountered HTTP error $e');
      }
      return false;
    }

    final ke2 = KE2.fromBytes(_opaque.suite.constants, responseBytes);
    final finishResult = await ake.finish(
      clientIdentity: _encoder.convert(username),
      serverIdentity: _encoder.convert(serverDomain),
      ke2: ke2,
    );

    try {
      await remoteClient.post(
        path: '/opaque/$username/login/finish',
        body: finishResult.ke3.serialize(),
      );
    } on _HttpException catch (e) {
      if (kDebugMode) {
        print('Encountered HTTP error $e');
      }
      return false;
    }

    _sessionKey = finishResult.sessionKey;
    _username = username;

    return true;
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
  final Uri baseUrl;

  _RemoteClient({required String domain}) : baseUrl = Uri.https(domain, '');

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
