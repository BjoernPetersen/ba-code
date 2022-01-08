import 'package:convert/convert.dart';
import 'package:opaque/src/oprf/uniform_message_expander.dart';
import 'package:opaque/src/oprf/util.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

void main() {
  group('irtf-test-vectors', () {
    group('sha256', () {
      final dst = 'QUUX-V01-CS02-with-expander-SHA256-128';
      final expanderFactory = UniformMessageExpander.sha256;

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg: '',
        dst: dst,
        uniformBytes:
            '68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg: 'abc',
        dst: dst,
        uniformBytes:
            'd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg: 'abcdef0123456789',
        dst: dst,
        uniformBytes:
            'eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg:
            'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
        dst: dst,
        uniformBytes:
            'b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg:
            'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dst: dst,
        uniformBytes:
            '4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c',
      );
    });

    group('sha512', () {
      final dst = 'QUUX-V01-CS02-with-expander-SHA512-256';
      final expanderFactory = UniformMessageExpander.sha512;

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg: '',
        dst: dst,
        uniformBytes:
            '6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg: 'abc',
        dst: dst,
        uniformBytes:
            '0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg: 'abcdef0123456789',
        dst: dst,
        uniformBytes:
            '087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg:
            'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
        dst: dst,
        uniformBytes:
            '7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3',
      );

      expandMessageTest(
        expanderFactory: expanderFactory,
        msg:
            'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dst: dst,
        uniformBytes:
            '57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4',
      );
    });
  });
}

expandMessageTest({
  required UniformMessageExpander Function({int lengthInBytes}) expanderFactory,
  required String msg,
  required String dst,
  required String uniformBytes,
  int lengthInBytes = 0x20,
}) {
  test('$msg-$dst', () async {
    final expander = expanderFactory(
      lengthInBytes: lengthInBytes,
    );
    final expanded = await expander.expand(
      msg.asciiBytes(),
      dst.asciiBytes(),
    );
    final encoded = hex.encode(expanded);
    expect(encoded, uniformBytes);
  });
}
