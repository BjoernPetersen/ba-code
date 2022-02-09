import 'package:opaque/src/opaque/opaque_base.dart';
import 'package:opaque/src/opaque/server/offline_registration.dart';
import 'package:opaque/src/opaque/server/online_ake.dart';
import 'package:opaque/src/opaque/state.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/opaque/mhf.dart';
export 'package:opaque/src/opaque/state.dart';
export 'package:opaque/src/opaque/suite.dart';
export 'package:opaque/src/oprf/oprf.dart' show KeyPair;

class Opaque extends OpaqueBase {
  Opaque(Suite suite) : super(suite);

  /// Actions relevant for the registration phase.
  OfflineRegistration get offlineRegistration => OfflineRegistrationImpl(this);

  /// Actions relevant for the login phase.
  /// The [dhContext] may be used as a domain separator for the
  /// Diffie-Hellman handshake, but it's optional.
  OnlineAke getOnlineAke(ServerState state, {Bytes? dhContext}) =>
      OnlineAkeImpl(
        this,
        dhContext ?? Bytes(0),
        state,
      );
}
