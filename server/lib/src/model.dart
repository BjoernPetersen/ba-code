import 'package:opaque/server.dart';

class StorageEntry {
  final RegistrationRecord registrationRecord;
  final Bytes oprfSeed;

  StorageEntry({
    required this.registrationRecord,
    required this.oprfSeed,
  });
}
