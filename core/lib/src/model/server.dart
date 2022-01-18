import 'package:opaque/src/model/common.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/model/common.dart';

class RegistrationRecord {
  /// The client's encoded public key, corresponding to the private
  /// key client_private_key.
  final Bytes clientPublicKey;

  /// A key used by the server to preserve confidentiality of the envelope during login.
  final Bytes maskingKey;

  /// The client's Envelope structure.
  final Envelope envelope;

  RegistrationRecord({
    required this.clientPublicKey,
    required this.maskingKey,
    required this.envelope,
  });

  static int size(Constants constants) {
    return constants.Npk + constants.Nh + Envelope.size(constants);
  }

  factory RegistrationRecord.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    final clientPublicKey = bytes.slice(0, constants.Npk);
    final maskingKey = bytes.slice(constants.Npk, constants.Nh);
    final envelope = Envelope.fromBytes(
      constants,
      bytes.slice(size(constants) - Envelope.size(constants)),
    );
    return RegistrationRecord(
      clientPublicKey: clientPublicKey,
      maskingKey: maskingKey,
      envelope: envelope,
    );
  }
}
