import 'dart:convert';
import 'dart:isolate';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:opaque/client.dart';
import 'package:opaque_app/secure_client.dart';
import 'package:opaque_app/state.dart';

Opaque get _opaque => Opaque(
      Suite.sha256p256(
        mhf: MemoryHardFunction.scrypt(),
      ),
    );

const _encoder = AsciiEncoder();

// TODO: don't hardcode this?
const serverDomain = 'opaque.bjoernpetersen.net';

Future<void> _asyncRegister(List args) async {
  final SendPort port = args[0];
  final String username = args[1];
  final String password = args[2];

  final result = await _doRegister(username: username, password: password);
  Isolate.exit(port, result);
}

Future<bool> _doRegister({
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

Future<void> _asyncLogin(List args) async {
  final SendPort port = args[0];
  final String username = args[1];
  final String password = args[2];

  final result = await _doLogin(username: username, password: password);
  Isolate.exit(port, result);
}

Future<Bytes?> _doLogin({
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
    return null;
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
    return null;
  }

  return finishResult.sessionKey;
}

class OpaqueHandler {
  String? _username;

  Bytes? _sessionKey;

  OpaqueHandler();

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
    final port = ReceivePort();
    await Isolate.spawn(_asyncRegister, [port.sendPort, username, password]);
    return await port.first;
  }

  Future<bool> login({
    required String username,
    required String password,
  }) async {
    final port = ReceivePort();
    await Isolate.spawn(_asyncLogin, [port.sendPort, username, password]);
    final Bytes? result = await port.first;
    if (result == null) {
      return false;
    }
    _username = username;
    _sessionKey = result;
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
