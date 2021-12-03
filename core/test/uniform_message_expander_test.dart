import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:opaque/src/oprf/uniform_message_expander.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

void main() {
  group('irtf-test-vectors', () {
    group('expandMessage', () {
      final dst = 'QUUX-V01-CS02-with-expander-SHA256-128';

      expandMessageTest(
        msg: '',
        dst: dst,
        uniformBytes:
            '68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235',
      );

      expandMessageTest(
        msg: 'abc',
        dst: dst,
        uniformBytes:
            'd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615',
      );

      expandMessageTest(
        msg: 'abcdef0123456789',
        dst: dst,
        uniformBytes:
            'eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1',
      );

      expandMessageTest(
        msg:
            'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
        dst: dst,
        uniformBytes:
            'b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9',
      );

      expandMessageTest(
        msg:
            'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dst: dst,
        uniformBytes:
            '4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c',
      );

      expandMessageTest(
        msg: 'abc',
        dst: dst,
        uniformBytes:
            'd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615',
      );

      expandMessageTest(
        msg: 'abc',
        dst: dst,
        uniformBytes:
            'd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615',
      );
    });
  });
}

expandMessageTest({
  required String msg,
  required String dst,
  required String uniformBytes,
  int lengthInBytes = 0x20,
}) {
  test('$msg-$dst', () async {
    final expander = UniformMessageExpander.sha256(
      lengthInBytes: lengthInBytes,
    );
    final expanded = await expander.expand(
      AsciiEncoder().convert(msg).buffer.asByteData(),
      dst,
    );
    final encoded = hex.encode(expanded);
    expect(encoded, uniformBytes);
  });
}
