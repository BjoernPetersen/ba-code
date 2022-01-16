import 'package:opaque/src/util.dart';

import '3dh.dart';

abstract class ClientState {
  abstract Bytes blind;
  abstract Bytes password;
  abstract Bytes clientSecret;
  abstract KE1 ke1;
}

abstract class ServerState {
  abstract Bytes expectedClientMac;
  abstract Bytes sessionKey;
}
