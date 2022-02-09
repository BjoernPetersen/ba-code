import 'dart:async';

import 'package:opaque/src/util.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';

abstract class MemoryHardFunction {
  factory MemoryHardFunction.identity() = _Identity;

  factory MemoryHardFunction.scrypt() => _Scrypt();

  FutureOr<Bytes> harden(Bytes input);
}

class _Identity implements MemoryHardFunction {
  @override
  FutureOr<Bytes> harden(Bytes input) => input;
}

class _Scrypt implements MemoryHardFunction {
  Scrypt _createAlgo(int keyLength) {
    final algo = Scrypt();
    algo.init(ScryptParameters(
      32768,
      8,
      1,
      keyLength,
      // We use no salt because we couldn't restore it afterwards
      Bytes(0),
    ));
    return algo;
  }

  @override
  FutureOr<Bytes> harden(Bytes input) {
    final algo = _createAlgo(input.length);
    return algo.process(input);
  }
}
