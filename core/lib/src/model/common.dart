import 'dart:typed_data';

export 'package:opaque/src/model/exception.dart';

typedef Bytes = Uint8List;

class Constants {
  // ignore: non_constant_identifier_names
  final int Nn = 32;

  // ignore: non_constant_identifier_names
  final int Nseed = 32;

  // ignore: non_constant_identifier_names
  final int Nh;

  // ignore: non_constant_identifier_names
  final int Npk;

  // ignore: non_constant_identifier_names
  final int Nsk;

  // ignore: non_constant_identifier_names
  final int Nm;

  // ignore: non_constant_identifier_names
  final int Nx;

  // ignore: non_constant_identifier_names
  final int Nok;

  const Constants({
    // ignore: non_constant_identifier_names
    required this.Nh,
    // ignore: non_constant_identifier_names
    required this.Npk,
    // ignore: non_constant_identifier_names
    required this.Nsk,
    // ignore: non_constant_identifier_names
    required this.Nm,
    // ignore: non_constant_identifier_names
    required this.Nx,
    // ignore: non_constant_identifier_names
    required this.Nok,
  });
}

/// OPAQUE makes use of a structure called Envelope to manage client
/// credentials. The client creates its Envelope on registration and sends it to
/// the server for storage. On every login, the server sends this Envelope to
/// the client so it can recover its key material for use in the AKE.
class Envelope {
  /// A unique nonce of length Nn used to protect this Envelope.
  final Bytes nonce;

  /// Authentication tag protecting the contents of the envelope,
  /// covering the envelope [nonce], and [CleartextCredentials].
  final Bytes authTag;

  Envelope({
    required this.nonce,
    required this.authTag,
  });

  factory Envelope.fromBytes(Constants constants, Bytes bytes) {
    return Envelope(
      nonce: bytes.sublist(0, constants.Nn),
      authTag: bytes.sublist(constants.Nn),
    );
  }

  List<Bytes> asBytesList() => [nonce, authTag];

  Bytes toBytes() => Uint8List.fromList([
        for (final bytes in asBytesList()) ...bytes,
      ]);
}

class RegistrationRequest {
  /// A serialized OPRF group element.
  final Bytes data;

  RegistrationRequest({required this.data});
}

class RegistrationResponse {
  /// A serialized OPRF group element.
  final Bytes data;

  /// The server's encoded public key that will be used for the
  /// online authenticated key exchange stage.
  final Bytes serverPublicKey;

  RegistrationResponse({
    required this.data,
    required this.serverPublicKey,
  });

  factory RegistrationResponse.fromBytes(Constants constants, Bytes bytes) {
    final dataLength = constants.Npk;
    final data = bytes.sublist(0, dataLength);
    final serverPublicKey = bytes.sublist(dataLength);
    return RegistrationResponse(data: data, serverPublicKey: serverPublicKey);
  }
}

class CredentialRequest {
  /// A serialized OPRF group element.
  final Bytes data;

  CredentialRequest({required this.data});

  List<Bytes> asBytesList() => [data];
}

class CredentialResponse {
  /// A serialized OPRF group element.
  final Bytes data;

  /// A nonce used for the confidentiality of the masked_response field.
  final Bytes maskingNonce;

  /// An encrypted form of the server's public key and the client's Envelope structure.
  final Bytes maskedResponse;

  CredentialResponse({
    required this.data,
    required this.maskingNonce,
    required this.maskedResponse,
  });

  List<Bytes> asBytesList() => [data, maskingNonce, maskedResponse];
}

class AuthInit {
  /// A fresh randomly generated nonce of length Nn.
  final Bytes clientNonce;

  /// Client ephemeral key share of fixed size Npk.
  final Bytes clientKeyshare;

  AuthInit({
    required this.clientNonce,
    required this.clientKeyshare,
  });

  List<Bytes> asBytesList() => [clientNonce, clientKeyshare];
}

class AuthResponse {
  /// A fresh randomly generated nonce of length Nn.
  final Bytes serverNonce;

  /// Server ephemeral key share of fixed size Npk, where Npk depends on the
  /// corresponding prime order group.
  final Bytes serverKeyshare;

  /// An authentication tag computed over the handshake transcript
  /// computed using Km2.
  final Bytes serverMac;

  AuthResponse({
    required this.serverNonce,
    required this.serverKeyshare,
    required this.serverMac,
  });

  AuthResponse withServerMac(Bytes serverMac) => AuthResponse(
        serverNonce: serverNonce,
        serverKeyshare: serverKeyshare,
        serverMac: serverMac,
      );
}

class AuthFinish {
  /// An authentication tag computed over the handshake transcript
  /// computed using Km2.
  final Bytes clientMac;

  AuthFinish({required this.clientMac});
}
