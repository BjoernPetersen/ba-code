import 'package:opaque/src/util.dart';

abstract class MemoryHardFunction {
  factory MemoryHardFunction.identity() = _Identity;

  // TODO implement PBKDF2, scrypt or argon2

  Future<Bytes> harden(Bytes input);
}

class _Identity implements MemoryHardFunction {
  @override
  Future<Bytes> harden(Bytes input) => Future.value(input);
}
