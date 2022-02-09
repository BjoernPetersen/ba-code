import 'dart:async';
import 'dart:convert';

import 'package:opaque/server.dart';
import 'package:opaque_server/src/model.dart';
import 'package:opaque_server/src/state.dart';

export 'package:opaque/server.dart' show Bytes, usernameHeader;

class OpaqueManager {
  static final _encoder = AsciiEncoder();
  final Opaque _opaque;
  final Map<String, StorageEntry> _storage;
  final Map<String, ServerState> _statesByUsername;
  late final Future<KeyPair> _keyPair;

  OpaqueManager()
      : _opaque = Opaque(Suite.sha256p256(
          mhf: MemoryHardFunction.scrypt(),
        )),
        _statesByUsername = {},
        _storage = {} {
    _keyPair = _opaque.generateAuthKeyPair();
  }

  Future<StorageEntry?> _loadStorageEntry(String username) async {
    return _storage[username];
  }

  FutureOr<void> _storeStorageEntry(
    String username,
    StorageEntry entry,
  ) {
    final existing = _storage[username];
    if (existing != null && existing.registrationRecord != null) {
      throw StateError('Cannot override existing registration');
    }
    _storage[username] = entry;
  }

  FutureOr<ServerState?> _loadState(String username) {
    return _statesByUsername[username];
  }

  Future<Bytes> initRegistration(
    String username,
    Bytes requestBytes,
  ) async {
    final request = RegistrationRequest.fromBytes(
      _opaque.suite.constants,
      requestBytes,
    );
    final registration = _opaque.offlineRegistration;
    final keyPair = await _keyPair;
    final oprfSeed = await registration.generateOprfSeed();
    final response = await registration.createRegistrationResponse(
      request: request,
      serverPublicKey: keyPair.public,
      credentialIdentifier: _encoder.convert(username),
      oprfSeed: oprfSeed,
    );
    final storageEntry = StorageEntry(
      registrationRecord: null,
      oprfSeed: oprfSeed,
    );
    await _storeStorageEntry(username, storageEntry);
    return response.serialize();
  }

  Future<void> finalizeRegistration(String username, Bytes recordBytes) async {
    final record = RegistrationRecord.fromBytes(
      _opaque.suite.constants,
      recordBytes,
    );
    final entry = await _loadStorageEntry(username);
    if (entry == null) {
      throw StateError('Unknown user');
    }
    if (entry.registrationRecord != null) {
      throw StateError('Already registered');
    }
    final newEntry = StorageEntry(
      registrationRecord: record,
      oprfSeed: entry.oprfSeed,
    );
    await _storeStorageEntry(username, newEntry);
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

    final registrationRecord = storageEntry.registrationRecord;
    if (registrationRecord == null) {
      throw StateError('Registration has not finished');
    }

    final state = MemoryServerState();
    _statesByUsername[username] = state;
    final ake = _opaque.getOnlineAke(state);

    final keyPair = await _keyPair;
    final clientIdentity = _encoder.convert(username);

    final ke2 = await ake.init(
      // TODO: don't hardcode this?
      serverIdentity: _encoder.convert('opaque.bjoernpetersen.net'),
      serverPrivateKey: keyPair.private,
      serverPublicKey: keyPair.public,
      record: registrationRecord,
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
    final ake = _opaque.getOnlineAke(state);

    final sessionKey = await ake.serverFinish(ke3: ke3);
    return SessionSecurity(sessionKey);
  }
}
