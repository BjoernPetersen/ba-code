import 'package:opaque/src/util.dart';

export 'package:opaque/src/opaque/model/exception.dart';

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
}

class CredentialsRequest {
  /// A serialized OPRF group element.
  final Bytes data;

  CredentialsRequest({required this.data});
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
}

class AuthFinish {
  /// An authentication tag computed over the handshake transcript
  /// computed using Km2.
  final Bytes clientMac;

  AuthFinish({required this.clientMac});
}

class StoreResult {
  /// the client's [Envelope] structure.
  final Envelope envelope;

  /// the client's AKE public key.
  final Bytes clientPublicKey;

  /// a key used by the server to encrypt the envelope during login.
  final Bytes maskingKey;

  /// an additional client key.
  final Bytes exportKey;

  StoreResult({
    required this.envelope,
    required this.clientPublicKey,
    required this.maskingKey,
    required this.exportKey,
  });
}

class RecoverResult {
  /// The encoded client private key for the AKE protocol.
  final Bytes clientPrivateKey;

  /// an additional client key.
  final Bytes exportKey;

  RecoverResult({
    required this.clientPrivateKey,
    required this.exportKey,
  });
}
