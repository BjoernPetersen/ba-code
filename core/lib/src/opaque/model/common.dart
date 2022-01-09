import 'package:opaque/src/util.dart';

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
