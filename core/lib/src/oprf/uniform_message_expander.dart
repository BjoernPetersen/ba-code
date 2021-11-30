import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

class UniformMessageExpander {
  final HashAlgorithm _hash;
  final int _lParam;
  final Uint8List _domainSeparator;

  UniformMessageExpander._(
    this._hash,
    this._lParam,
    this._domainSeparator,
  );

  factory UniformMessageExpander.sha256(
    String domainSeparator,
  ) =>
      UniformMessageExpander._(
        Sha256(),
        48,
        AsciiEncoder().convert(domainSeparator),
      );

  factory UniformMessageExpander.sha384(
    String domainSeparator,
  ) =>
      UniformMessageExpander._(
        Sha384(),
        72,
        AsciiEncoder().convert(domainSeparator),
      );

  Future<List<int>> expand(String message) async {
    // TODO: this might not be entirely correct, should use L = 72
    final hashSink = _hash.newHashSink();

    try {
      hashSink.add(_domainSeparator);
      final data = AsciiEncoder().convert(message);
      hashSink.add(data.buffer.asUint8List());
    } finally {
      hashSink.close();
    }

    final hash = await hashSink.hash();
    return hash.bytes;
  }
}

enum DigestAlgo {
  sha256,
  sha384,
}
