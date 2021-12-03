import 'package:opaque/src/oprf/data_conversion.dart';
import 'package:test/test.dart';

void main() {
  group('I2OSP', () {
    test(
      'fail for negative length',
      () => expect(() => intToBytes(BigInt.from(123), -1), throwsArgumentError),
    );

    test(
      'length is too short',
      () => expect(
        () => intToBytes(BigInt.from(65536), 2),
        throwsArgumentError,
      ),
    );

    test(
      'length is correct',
      () => expect(
        intToBytes(BigInt.from(0), 64),
        hasLength(64),
      ),
    );

    group('happy paths', () {
      final expectedByParams = {
        [255, 4]: [0, 0, 0, 255],
        [256, 4]: [0, 0, 1, 0],
        [65535, 2]: [255, 255],
      };

      for (final entry in expectedByParams.entries) {
        final params = entry.key;
        test(
          '(${params[0]}, ${params[1]})',
          () => expect(
            intToBytes(BigInt.from(params[0]), params[1]),
            entry.value,
          ),
        );
      }
    });
  });

  group('round trip', () {
    final testValues = {
      255: 4,
      256: 4,
      65535: 2,
    };

    for (final entry in testValues.entries) {
      final number = BigInt.from(entry.key);
      final length = entry.value;
      test(
        '($number, $length)',
        () => expect(
          bytesToInt(intToBytes(number, length)),
          number,
        ),
      );
    }
  });
}
