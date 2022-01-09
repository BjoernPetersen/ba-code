import 'package:opaque/src/opaque/model/common.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/opaque/model/common.dart';

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
}
