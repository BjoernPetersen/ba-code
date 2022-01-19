import 'package:opaque/client.dart';

class MemoryClientState implements ClientState {
  Bytes? _blind;
  Bytes? _clientSecret;
  KE1? _ke1;
  Bytes? _password;

  @override
  Bytes get blind {
    final result = _blind;
    if (result == null) {
      throw StateError('tried to access state value before setting it');
    }
    return result;
  }

  @override
  set blind(Bytes value) => _blind = value;

  @override
  Bytes get clientSecret {
    final result = _clientSecret;
    if (result == null) {
      throw StateError('tried to access state value before setting it');
    }
    return result;
  }

  @override
  set clientSecret(Bytes value) => _clientSecret = value;

  @override
  KE1 get ke1 {
    final result = _ke1;
    if (result == null) {
      throw StateError('tried to access state value before setting it');
    }
    return result;
  }

  @override
  set ke1(KE1 value) => _ke1 = value;

  @override
  Bytes get password {
    final result = _password;
    if (result == null) {
      throw StateError('tried to access state value before setting it');
    }
    return result;
  }

  @override
  set password(Bytes value) => _password = value;
}
