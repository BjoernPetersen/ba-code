import 'dart:typed_data';

import 'package:opaque/src/util.dart';

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

  // ignore: non_constant_identifier_names
  final int Noe;

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
    // ignore: non_constant_identifier_names
    required this.Noe,
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

  static int size(Constants constants) {
    return constants.Nn + constants.Nm;
  }

  factory Envelope.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return Envelope(
      nonce: bytes.slice(0, constants.Nn),
      authTag: bytes.slice(constants.Nn, constants.Nm),
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

  factory RegistrationRequest.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != constants.Noe) {
      throw ArgumentError('Invalid data size', 'bytes');
    }

    return RegistrationRequest(data: bytes);
  }

  List<Bytes> asBytesList() => [data];

  Bytes serialize() => concatBytes(asBytesList());
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

  static int size(Constants constants) {
    return constants.Noe + constants.Npk;
  }

  factory RegistrationResponse.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    final data = bytes.slice(0, constants.Noe);
    final serverPublicKey = bytes.slice(constants.Noe, constants.Npk);
    return RegistrationResponse(data: data, serverPublicKey: serverPublicKey);
  }

  List<Bytes> asBytesList() => [data, serverPublicKey];

  Bytes serialize() => concatBytes(asBytesList());
}

class CredentialRequest {
  /// A serialized OPRF group element.
  final Bytes data;

  CredentialRequest({required this.data});

  List<Bytes> asBytesList() => [data];

  static int size(Constants constants) {
    return constants.Noe;
  }

  factory CredentialRequest.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return CredentialRequest(data: bytes);
  }
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

  static int size(Constants constants) {
    return constants.Noe +
        constants.Nn +
        constants.Npk +
        Envelope.size(constants);
  }

  factory CredentialResponse.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return CredentialResponse(
      data: bytes.slice(0, constants.Noe),
      maskingNonce: bytes.slice(constants.Noe, constants.Nn),
      maskedResponse: bytes.slice(constants.Noe + constants.Nn),
    );
  }
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

  static int size(Constants constants) {
    return constants.Nn + constants.Npk;
  }

  factory AuthInit.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    final clientNonce = bytes.slice(0, constants.Nn);
    final clientKeyshare = bytes.slice(constants.Nn, constants.Npk);
    return AuthInit(
      clientNonce: clientNonce,
      clientKeyshare: clientKeyshare,
    );
  }
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

  List<Bytes> asBytesList() => [
        serverNonce,
        serverKeyshare,
        serverMac,
      ];

  static int size(Constants constants) {
    return constants.Nn + constants.Npk + constants.Nm;
  }

  factory AuthResponse.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return AuthResponse(
      serverNonce: bytes.slice(0, constants.Nn),
      serverKeyshare: bytes.slice(constants.Nn, constants.Npk),
      serverMac: bytes.slice(constants.Nn + constants.Npk),
    );
  }
}

class AuthFinish {
  /// An authentication tag computed over the handshake transcript
  /// computed using Km2.
  final Bytes clientMac;

  AuthFinish({required this.clientMac});

  List<Bytes> asBytesList() => [clientMac];

  factory AuthFinish.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != constants.Nm) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return AuthFinish(clientMac: bytes);
  }
}

class KE1 {
  final CredentialRequest credentialRequest;
  final AuthInit authInit;

  KE1({
    required this.credentialRequest,
    required this.authInit,
  });

  List<Bytes> asBytesList() => [
        ...credentialRequest.asBytesList(),
        ...authInit.asBytesList(),
      ];

  static int size(Constants constants) {
    return CredentialRequest.size(constants) + AuthInit.size(constants);
  }

  factory KE1.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return KE1(
      credentialRequest: CredentialRequest.fromBytes(
        constants,
        bytes.slice(0, CredentialRequest.size(constants)),
      ),
      authInit: AuthInit.fromBytes(
        constants,
        bytes.slice(CredentialRequest.size(constants)),
      ),
    );
  }
}

class KE2 {
  final CredentialResponse credentialResponse;
  final AuthResponse authResponse;

  KE2({
    required this.credentialResponse,
    required this.authResponse,
  });

  KE2 withServerMac(Bytes serverMac) => KE2(
        credentialResponse: credentialResponse,
        authResponse: authResponse.withServerMac(serverMac),
      );

  List<Bytes> asBytesList() => [
        ...credentialResponse.asBytesList(),
        ...authResponse.asBytesList(),
      ];

  Bytes serialize() => concatBytes(asBytesList());

  static int size(Constants constants) {
    return CredentialResponse.size(constants) + AuthResponse.size(constants);
  }

  factory KE2.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return KE2(
      credentialResponse: CredentialResponse.fromBytes(
        constants,
        bytes.slice(0, CredentialResponse.size(constants)),
      ),
      authResponse: AuthResponse.fromBytes(
        constants,
        bytes.slice(
          CredentialResponse.size(constants),
          AuthResponse.size(constants),
        ),
      ),
    );
  }
}

typedef KE3 = AuthFinish;
