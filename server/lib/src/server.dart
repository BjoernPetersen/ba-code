import 'dart:async';
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;

class Server {
  Server._();

  FutureOr<Response> call(Request request) {
    return Response.ok('OK');
  }

  static Future<void> launch() async {
    await io.serve(Server._(), InternetAddress.anyIPv4, 8080);
  }
}
