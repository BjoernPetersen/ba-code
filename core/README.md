# Core Module

This package contains the actual OPAQUE implementation.

## Usage

Depending on whether you implement the server or the client side, import either of these:

```dart
import 'package:opaque/client.dart';
// or
import 'package:opaque/server.dart';
```

Then choose a `Suite` to use (client and server must use the same suite) and instantiate the
`Opaque` class:

```dart
final opaque = Opaque(Suite.sha256p256());
```

The interface of the `Opaque` class is rather straightforward and split by
registration and login phase. If the correct module was imported, only the
methods relevant for the current use case (client or server) are visible.
