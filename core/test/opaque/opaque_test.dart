import 'dart:async';

import 'package:opaque/server.dart';
import 'package:test/test.dart';

import '../util.dart';
import 'state_impl.dart';
import 'test_vectors.dart';

void main() {
  group('full process p256', () {
    _test(Suite.sha256p256());
  });
  group(
    'full process p384',
    () {
      _test(Suite.sha384p384());
    },
    skip: true,
  );

  group('login using vector data', () {
    for (final vector in vectors) {
      group(vector.name, () {
        _testLogin(
          opaque: Opaque(vector.suite),
          password: vector.input.password.hexDecode(),
          credentialIdentifier: vector.input.credentialIdentifier.hexDecode(),
          clientIdentity: vector.input.clientIdentity?.hexDecode() ??
              vector.intermediate.clientPublicKey.hexDecode(),
          serverIdentity: vector.input.serverIdentity?.hexDecode() ??
              vector.input.serverPublicKey.hexDecode(),
          oprfSeedFuture: vector.input.oprfSeed.hexDecode(),
          serverKeyPairFuture: KeyPair(
            private: vector.input.serverPrivateKey.hexDecode(),
            public: vector.input.serverPublicKey.hexDecode(),
          ),
          recordFuture: RegistrationRecord.fromBytes(
            vector.suite.constants,
            vector.output.registrationUpload.hexDecode(),
          ),
          context: vector.context.hexDecode(),
        );
      });
    }
  });
}

void _test(Suite suite) {
  final opaque = Opaque(suite);

  final password = 'password'.asciiBytes();
  final clientIdentity = 'user'.asciiBytes();
  final serverIdentity = 'server'.asciiBytes();

  final loadKeyPair = Completer<KeyPair>();
  final Future<KeyPair> serverKeyPair = loadKeyPair.future;
  final loadOprfSeed = Completer<Bytes>();
  final Future<Bytes> oprfSeed = loadOprfSeed.future;
  final loadRecord = Completer<RegistrationRecord>();
  final Future<RegistrationRecord> record = loadRecord.future;
  setUpAll(() async {
    final serverKeyPair = await opaque.generateAuthKeyPair();
    loadKeyPair.complete(serverKeyPair);
    final oprfSeed = await opaque.generateOprfSeed();
    loadOprfSeed.complete(oprfSeed);

    final reg = opaque.offlineRegistration;
    final requestResult = await reg.createRegistrationRequest(
      password: password,
    );
    final response = await reg.createRegistrationResponse(
      request: requestResult.request,
      serverPublicKey: serverKeyPair.public,
      credentialIdentifier: clientIdentity,
      oprfSeed: oprfSeed,
    );
    final finalized = await reg.finalizeRequest(
      password: password,
      blind: requestResult.blind,
      response: response,
      serverIdentity: serverIdentity,
      clientIdentity: clientIdentity,
    );
    final record = finalized.record;
    loadRecord.complete(record);
  });

  group('login', () {
    _testLogin(
      opaque: opaque,
      password: password,
      credentialIdentifier: clientIdentity,
      clientIdentity: clientIdentity,
      serverIdentity: serverIdentity,
      oprfSeedFuture: oprfSeed,
      serverKeyPairFuture: serverKeyPair,
      recordFuture: record,
      context: null,
    );
  });
}

void _testLogin({
  required Opaque opaque,
  required Bytes password,
  required Bytes credentialIdentifier,
  required Bytes clientIdentity,
  required Bytes serverIdentity,
  required FutureOr<Bytes> oprfSeedFuture,
  required FutureOr<KeyPair> serverKeyPairFuture,
  required FutureOr<RegistrationRecord> recordFuture,
  required Bytes? context,
}) {
  final clientState = MemoryClientState();
  final serverState = MemoryServerState();

  final clientAke = opaque.getClientAke(
    clientState,
    dhContext: context,
  );
  final serverAke = opaque.getServerAke(
    serverState,
    dhContext: context,
  );

  late final KE2 ke2;
  setUpAll(() async {
    final ke1 = await clientAke.init(
      password: password,
    );
    final serverKeyPair = await serverKeyPairFuture;
    final record = await recordFuture;
    final oprfSeed = await oprfSeedFuture;
    ke2 = await serverAke.init(
      serverIdentity: serverIdentity,
      serverPrivateKey: serverKeyPair.private,
      serverPublicKey: serverKeyPair.public,
      record: record,
      credentialIdentifier: credentialIdentifier,
      oprfSeed: oprfSeed,
      ke1: ke1,
      clientIdentity: clientIdentity,
    );
  });

  test('Client finishes', () async {
    expect(
      clientAke.finish(
        clientIdentity: clientIdentity,
        serverIdentity: serverIdentity,
        ke2: ke2,
      ),
      completes,
    );
  });

  test('Server finishes', () async {
    final result = await clientAke.finish(
      clientIdentity: clientIdentity,
      serverIdentity: serverIdentity,
      ke2: ke2,
    );
    final finish = serverAke.serverFinish(ke3: result.ke3);
    await expectLater(finish, completes);
    final finished = await finish;
    expect(finished, result.sessionKey);
  });
}
