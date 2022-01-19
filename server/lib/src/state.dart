import 'package:opaque/server.dart';

class MemoryServerState implements ServerState {
  Bytes? _expectedClientMac;
  Bytes? _sessionKey;

  @override
  Bytes get expectedClientMac {
    final result = _expectedClientMac;
    if (result == null) {
      throw StateError('tried to access state value before setting it');
    }
    return result;
  }

  @override
  set expectedClientMac(Bytes value) => _expectedClientMac = value;

  @override
  Bytes get sessionKey {
    final result = _sessionKey;
    if (result == null) {
      throw StateError('tried to access state value before setting it');
    }
    return result;
  }

  @override
  set sessionKey(Bytes value) => _sessionKey = value;
}
