import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:opaque/src/oprf/data_conversion.dart';

class UniformMessageExpander {
  final HashAlgorithm _hasher;
  final int _lengthInBytes;

  UniformMessageExpander._(
    this._hasher,
    this._lengthInBytes,
  );

  factory UniformMessageExpander.sha256({
    int lengthInBytes = 48,
  }) =>
      UniformMessageExpander._(
        Sha256(),
        lengthInBytes,
      );

  factory UniformMessageExpander.sha384({
    int lengthInBytes = 72,
  }) =>
      UniformMessageExpander._(
        Sha384(),
        lengthInBytes,
      );

  Future<List<int>> _hash(List<int> input) async {
    final hash = await _hasher.hash(input);
    return hash.bytes;
  }

  /// Implementation of
  /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
  Future<List<int>> expand(ByteBuffer message, String domainSeparator) async {
    final domainSeparatorBytes = AsciiEncoder().convert(domainSeparator);
    final ell = (_lengthInBytes / _hasher.hashLengthInBytes).ceil();
    if (ell > 255) {
      throw ArgumentError.value(_lengthInBytes, 'lengthInBytes');
    }

    final domainSeparatorLengthBytes = intToBytes(
      BigInt.from(domainSeparatorBytes.length),
      1,
    );
    final dstPrime = domainSeparatorBytes + domainSeparatorLengthBytes;
    final zPad = intToBytes(BigInt.zero, _hasher.blockLengthInBytes);
    final lengthBytes = intToBytes(BigInt.from(_lengthInBytes), 2);

    final messageBytes = message.asUint8List();
    final List<int> msgPrime = [
      ...zPad,
      ...messageBytes,
      ...lengthBytes,
      0,
      ...dstPrime,
    ];

    final uniformBytes = List.filled(ell, List.empty());
    final b0 = await _hash(msgPrime);
    uniformBytes[0] = await _hash(b0 + [1] + dstPrime);
    for (int i = 2; i <= ell; i += 1) {
      final previous = uniformBytes[i - 2];
      final b0XorPrevious = [
        for (int i = 0; i < _hasher.hashLengthInBytes; i += 1)
          b0[i] ^ previous[i]
      ];
      uniformBytes[i - 1] = await _hash(b0XorPrevious + [i] + dstPrime);
    }

    final List<int> result = [for (final bytes in uniformBytes) ...bytes];
    return Uint8List.fromList(result).sublist(0, _lengthInBytes);
  }
}

enum DigestAlgo {
  sha256,
  sha384,
}
