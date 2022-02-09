import 'package:convert/convert.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/util.dart';

extension HexEncode on Bytes {
  String hexEncode() {
    return hex.encode(this);
  }
}

extension HexDecode on String {
  Bytes hexDecode() {
    return Bytes.fromList(hex.decode(this));
  }
}
