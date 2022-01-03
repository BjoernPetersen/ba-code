import 'dart:convert';
import 'dart:typed_data';

typedef Bytes = Uint8List;

Bytes concatBytes(List<Bytes> byteLists) {
  final builder = BytesBuilder(copy: false);
  for (final list in byteLists) {
    builder.add(list);
  }
  return builder.toBytes();
}

@deprecated
ByteBuffer concatBuffers(List<ByteBuffer> buffers) {
  final builder = BytesBuilder(copy: false);
  for (final buffer in buffers) {
    builder.add(buffer.asUint8List());
  }
  return builder.toBytes().buffer;
}

extension Ascii on String {
  static final _encoder = AsciiEncoder();

  Bytes asciiBytes() {
    return _encoder.convert(this);
  }
}
