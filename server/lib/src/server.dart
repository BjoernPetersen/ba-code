import 'dart:async';
import 'dart:io';

import 'package:opaque/server.dart';
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
    final body = await request.read().toBytes();
    final Bytes response;
    try {
      response = await _opaque.initRegistration(username, body);
    } on ArgumentError {
      return Response(HttpStatus.badRequest);
    } on StateError {
      // TODO: change exception type
      return Response(HttpStatus.conflict);
    }

    return Response.ok(response);
  }

  @Route.post('/opaque/<username>/registration/finalize')
  Future<Response> finalizeRegistration(
    Request request,
    String username,
  ) async {
    final body = await request.read().toBytes();
    try {
      await _opaque.finalizeRegistration(username, body);
    } on ArgumentError {
      return Response(HttpStatus.badRequest);
    } on StateError {
      // TODO: change exception type
      return Response(HttpStatus.conflict);
    }

    return Response(HttpStatus.noContent);
  }

  @Route.post('/opaque/<username>/login/init')
  Future<Response> initLogin(Request request, String username) async {
    final body = await request.read().toBytes();
    final Bytes response;
    try {
      response = await _opaque.initLogin(username, body);
    } on ArgumentError {
      return Response(HttpStatus.badRequest);
    }

    return Response.ok(response);
  }

  @Route.post('/opaque/<username>/login/finish')
  Future<Response> finishLogin(Request request, String username) async {
    final session = await _opaque.finishLogin(
      username,
      await request.read().toBytes(),
    );
    _sessionManager.setSession(username, session);
    return Response(HttpStatus.noContent);
  }

  Future<Response> authenticated(
    Request request,
    FutureOr<Response> Function(List<int> data) handler,
  ) async {
    final username = request.headers[usernameHeader];
    if (username == null) {
      return Response(
        HttpStatus.unauthorized,
        body: 'Missing $usernameHeader header',
      );
    }

    final session = _sessionManager.getSession(username);
    if (session == null) {
      // TODO: could add a WWW-Authenticate header here
      // example: WWW-Authenticate: MyAuthScheme realm="http://example.com"
      return Response(HttpStatus.unauthorized);
    }

    final decryptedData = await session.decrypt(await request.read().toBytes());
    final handlerResponse = await handler(decryptedData);
    final encryptedBody = await session.encrypt(
      await handlerResponse.read().toBytes(),
    );
    return handlerResponse.change(body: encryptedBody);
  }

  @Route.get('/')
  Future<Response> getRoot(Request request) async {
    return await authenticated(request, (data) {
      return Response.ok('Congratulations, you are authenticated!');
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
