import 'dart:async';
import 'dart:io';

import 'package:opaque_server/src/session.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';

import 'opaque.dart';

part 'server.g.dart';

class Server {
  late final Router _router;
  final OpaqueManager _opaque;
  final SessionManager _sessionManager;

  Server._()
      : _opaque = OpaqueManager(),
        _sessionManager = SessionManager() {
    _router = _$ServerRouter(this);
  }

  FutureOr<Response> call(Request request) => _router.call(request);

  @Route.post('/opaque/<username>/registration/init')
  Future<Response> initRegistration(Request request, String username) async {
    print('Init Registration');
    final body = await request.read().toBytes();
    final Bytes response;
    try {
      response = await _opaque.initRegistration(username, body);
    } on ArgumentError catch (e) {
      print('Init Registration BadRequest: $e');
      return Response(HttpStatus.badRequest);
    } on StateError catch (e) {
      print('Init Registration Conflict: $e');
      // TODO: change exception type
      return Response(HttpStatus.conflict);
    }

    print('Init Registration Success');
    return Response.ok(response);
  }

  @Route.post('/opaque/<username>/registration/finalize')
  Future<Response> finalizeRegistration(
    Request request,
    String username,
  ) async {
    print('Finalize Registration');
    final body = await request.read().toBytes();
    try {
      await _opaque.finalizeRegistration(username, body);
    } on ArgumentError catch (e) {
      print('Finalize Registration BadRequest: $e');
      return Response(HttpStatus.badRequest);
    } on StateError catch (e) {
      print('Finalize Registration Conflict: $e');
      // TODO: change exception type
      return Response(HttpStatus.conflict);
    }

    print('Finalize Registration Success (user $username)');
    return Response(HttpStatus.noContent);
  }

  @Route.post('/opaque/<username>/login/init')
  Future<Response> initLogin(Request request, String username) async {
    print('Init Login');
    final body = await request.read().toBytes();
    final Bytes response;
    try {
      response = await _opaque.initLogin(username, body);
    } on ArgumentError catch (e) {
      print('Init Login BadRequest $e');
      return Response(HttpStatus.badRequest);
    }

    print('Init Login Success');
    return Response.ok(response);
  }

  @Route.post('/opaque/<username>/login/finish')
  Future<Response> finishLogin(Request request, String username) async {
    print('Finish Login');

    final SessionSecurity session;
    try {
      session = await _opaque.finishLogin(
        username,
        await request.read().toBytes(),
      );
    } on StateError catch (e) {
      print('Finish Login StateError $e');
      return Response(HttpStatus.badRequest);
    } on HandshakeException catch (e) {
      print('Finish Login HandshakeException $e');
      return Response(HttpStatus.badRequest);
    }
    _sessionManager.setSession(username, session);
    print('Finish Login Success');
    return Response(HttpStatus.noContent);
  }

  Future<Response> authenticated(
    Request request,
    FutureOr<Response> Function(String username, List<int> data) handler,
  ) async {
    final username = request.headers[usernameHeader];
    if (username == null) {
      print('Unauthorized Attempt (missing header)');
      return Response(
        HttpStatus.unauthorized,
        body: 'Missing $usernameHeader header',
      );
    }

    final session = _sessionManager.getSession(username);
    if (session == null) {
      print('Unauthorized Attempt (no session)');
      // TODO: could add a WWW-Authenticate header here
      // example: WWW-Authenticate: MyAuthScheme realm="http://example.com"
      return Response(HttpStatus.unauthorized);
    }

    final encryptedData = await request.read().toBytes();
    final List<int> decryptedData;
    if (encryptedData.isEmpty) {
      decryptedData = List.empty();
    } else {
      decryptedData = await session.decrypt(encryptedData);
    }
    final handlerResponse = await handler(username, decryptedData);
    final encryptedBody = await session.encrypt(
      await handlerResponse.read().toBytes(),
    );
    return handlerResponse.change(body: encryptedBody);
  }

  @Route.get('/')
  Future<Response> getRoot(Request request) async {
    print('Attempting to get protected resource');
    return await authenticated(request, (username, data) {
      print('User $username is authenticated!');
      return Response.ok(
        'Congratulations!'
        ' If you can read this message,'
        ' you are successfully authenticated using the OPAQUE protocol.',
      );
    });
  }

  @Route.get('/health')
  FutureOr<Response> getHealth(Request request) {
    return Response.ok('OK');
  }

  static Future<void> launch() async {
    try {
      print('Launching server...');
      await io.serve(Server._(), InternetAddress.anyIPv4, 8080);
    } catch (e) {
      print('Encountered exception: $e');
      exit(1);
    }
  }
}

extension on Stream<List<int>> {
  Future<Bytes> toBytes() async {
    final builder = BytesBuilder(copy: false);
    await forEach((bytes) => builder.add(bytes));
    return builder.toBytes();
  }
}
