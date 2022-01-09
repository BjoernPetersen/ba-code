import 'package:opaque/src/util.dart';
import 'package:opaque/src/opaque/model/common.dart';
export 'package:opaque/src/opaque/model/common.dart';

class CleartextCredentials {
  /// The encoded server public key for the AKE protocol.
  final Bytes serverPublicKey;

  /// The server identity. This is typically a domain name, e.g., example.com.
  /// If not specified, it defaults to the server's public key.
  final Bytes serverIdentity;

  /// The client identity. This is an application-specific value,
  /// e.g., an e-mail address or an account name.
  /// If not specified, it defaults to the client's public key.
  final Bytes clientIdentity;

  CleartextCredentials({
    required this.serverPublicKey,
    required this.serverIdentity,
    required this.clientIdentity,
  });
}
