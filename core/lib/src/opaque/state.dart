import 'package:opaque/src/model/model.dart';

/// The client state, which should be persistent
/// for the duration of one login phase.
abstract class ClientState {
  abstract Bytes blind;
  abstract Bytes password;
  abstract Bytes clientSecret;
  abstract KE1 ke1;
}

/// The server state, which should be persistent
/// for the duration of one login phase.
abstract class ServerState {
  abstract Bytes expectedClientMac;
  abstract Bytes sessionKey;
}
