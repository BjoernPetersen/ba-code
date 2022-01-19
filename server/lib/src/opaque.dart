import 'dart:async';
import 'dart:convert';

import 'package:opaque/server.dart';
import 'package:opaque_server/src/model.dart';
import 'package:opaque_server/src/session.dart';
import 'package:opaque_server/src/state.dart';

class OpaqueManager {
  static final _encoder = AsciiEncoder();
  final Opaque _opaque;
  final Map<String, StorageEntry> _storage;
  final Map<String, ServerState> _statesByUsername;
  late final Future<KeyPair> _keyPair;

  OpaqueManager()
      : _opaque = Opaque(Suite.sha256p256()),
        _statesByUsername = {},
        _storage = {} {
    _keyPair = _opaque.generateAuthKeyPair();
  }

  Future<StorageEntry?> _loadStorageEntry(String username) async {
    return _storage[username];
  }

  FutureOr<ServerState?> _loadState(String username) {
    return _statesByUsername[username];
  }

  Future<Bytes> initLogin(String username, List<int> requestBytes) async {
    final ke1 = KE1.fromBytes(
      _opaque.suite.constants,
      Bytes.fromList(requestBytes),
    );
    final storageEntry = await _loadStorageEntry(username);
    if (storageEntry == null) {
      // TODO: these exceptions theoretically allow client enumeration attacks
      throw StateError('Unknown user $username');
    }

    final state = MemoryServerState();
    _statesByUsername[username] = state;
    final ake = _opaque.getServerAke(state);

    final keyPair = await _keyPair;
    final clientIdentity = _encoder.convert(username);

    final ke2 = await ake.init(
      // TODO: don't hardcode this
      serverIdentity: _encoder.convert('opaque.bjoernpetersen.net'),
      serverPrivateKey: keyPair.private,
      serverPublicKey: keyPair.public,
      record: storageEntry.registrationRecord,
      credentialIdentifier: clientIdentity,
      oprfSeed: storageEntry.oprfSeed,
      ke1: ke1,
      clientIdentity: clientIdentity,
    );

    return ke2.serialize();
  }

  Future<SessionSecurity> finishLogin(
      String username, List<int> requestBytes) async {
    final ke3 = KE3.fromBytes(
      _opaque.suite.constants,
      Bytes.fromList(requestBytes),
    );
    final state = await _loadState(username);
    if (state == null) {
      // TODO: these exceptions theoretically allow client enumeration attacks
      throw StateError('No state for user $username');
    }
    final ake = _opaque.getServerAke(state);

    final sessionKey = await ake.serverFinish(ke3: ke3);
    return SessionSecurity(sessionKey);
  }
}
