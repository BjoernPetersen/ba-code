import 'package:cryptography/cryptography.dart';
import 'package:opaque/src/data_conversion.dart';
import 'package:opaque/src/util.dart';

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

  factory UniformMessageExpander.sha512({
    int lengthInBytes = 98,
  }) =>
      UniformMessageExpander._(
        Sha512(),
        lengthInBytes,
      );

  Future<List<int>> _hash(List<int> input) async {
    final hash = await _hasher.hash(input);
    return hash.bytes;
  }

  /// Implementation of
  /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
  Future<List<int>> expand(
    Bytes message,
    Bytes domainSeparator,
  ) async {
    final ell = (_lengthInBytes / _hasher.hashLengthInBytes).ceil();
    if (ell > 255) {
      throw ArgumentError.value(_lengthInBytes, 'lengthInBytes');
    }

    final domainSeparatorLengthBytes = smallIntToBytes(
      domainSeparator.length,
      length: 1,
    );
    final dstPrime = domainSeparator + domainSeparatorLengthBytes;
    final zPad = smallIntToBytes(0, length: _hasher.blockLengthInBytes);
    final lengthBytes = smallIntToBytes(_lengthInBytes, length: 2);

    final messageBytes = message;
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
    return Bytes.fromList(result).sublist(0, _lengthInBytes);
  }
}
