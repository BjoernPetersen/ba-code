import 'package:opaque/src/opaque/opaque.dart';

class VectorInput {
  final String? clientIdentity;
  final String? serverIdentity;
  final String oprfSeed;
  final String credentialIdentifier;
  final String password;
  final String envelopeNonce;
  final String maskingNonce;
  final String serverPrivateKey;
  final String serverPublicKey;
  final String serverNonce;
  final String clientNonce;
  final String serverKeyshare;
  final String clientKeyshare;
  final String serverPrivateKeyshare;
  final String clientPrivateKeyshare;
  final String blindRegistration;
  final String blindLogin;

  VectorInput({
    this.clientIdentity,
    this.serverIdentity,
    required this.oprfSeed,
    required this.credentialIdentifier,
    required this.password,
    required this.envelopeNonce,
    required this.maskingNonce,
    required this.serverPrivateKey,
    required this.serverPublicKey,
    required this.serverNonce,
    required this.clientNonce,
    required this.serverKeyshare,
    required this.clientKeyshare,
    required this.serverPrivateKeyshare,
    required this.clientPrivateKeyshare,
    required this.blindRegistration,
    required this.blindLogin,
  });
}

class VectorIntermediate {
  final String clientPublicKey;
  final String authKey;
  final String randomizedPwd;
  final String envelope;
  final String handshakeSecret;
  final String serverMacKey;
  final String clientMacKey;
  final String oprfKey;

  VectorIntermediate({
    required this.clientPublicKey,
    required this.authKey,
    required this.randomizedPwd,
    required this.envelope,
    required this.handshakeSecret,
    required this.serverMacKey,
    required this.clientMacKey,
    required this.oprfKey,
  });
}

class VectorOutput {
  final String registrationRequest;
  final String registrationResponse;
  final String registrationUpload;
  final String ke1;
  final String ke2;
  final String ke3;
  final String exportKey;
  final String sessionKey;

  VectorOutput({
    required this.registrationRequest,
    required this.registrationResponse,
    required this.registrationUpload,
    required this.ke1,
    required this.ke2,
    required this.ke3,
    required this.exportKey,
    required this.sessionKey,
  });
}

class Vector {
  final String name;
  final Suite suite;
  final String context;
  final VectorInput input;
  final VectorIntermediate intermediate;
  final VectorOutput output;

  Vector({
    required this.name,
    required this.suite,
    required this.context,
    required this.input,
    required this.intermediate,
    required this.output,
  });
}

final vectors = [
  Vector(
    name: 'OPAQUE-3DH Real Test Vector 3',
    suite: Suite.sha256p256(mhf: MemoryHardFunction.identity()),
    context: '4f50415155452d504f43',
    input: VectorInput(
      oprfSeed:
          '77bfc065218c9a5593c952161b93193f025b3474102519e6984fa648310dd1bf',
      credentialIdentifier: '31323334',
      password: '436f7272656374486f72736542617474657279537461706c65',
      envelopeNonce:
          '2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4a8319',
      maskingNonce:
          'cb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b2',
      serverPrivateKey:
          '87ef09986545b295e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421b1d63d7a3',
      serverPublicKey:
          '025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dadec592d88406e25c2f2',
      serverNonce:
          '8018e88ecfc53891529278c47239f8fe6f1be88972721898ef81cc0a76a0b550',
      clientNonce:
          '967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e9019',
      serverKeyshare:
          '0242bc29993976185dacf6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a17',
      clientKeyshare:
          '03358b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398',
      serverPrivateKeyshare:
          'b1c0063e442238bdd89cd62b4c3ad31f016b68085d25f85613f5838cd7c6b16a',
      clientPrivateKeyshare:
          '10256ab078bc1edbaf79bee4cd28dd9db89179dcc9219bc8f388b533f5439099',
      blindRegistration:
          'd50e29b581d716c3c05c4a0d6110b510cb5c9959bee817fdeb1eabd7ccd74fee',
      blindLogin:
          '503d8495c6d04efaee8370c45fa1dfad70201edd140cec8ed6c73b5fcd15c478',
    ),
    intermediate: VectorIntermediate(
      clientPublicKey:
          '030f9b896400f6efd57c69a41b05ffedc456f041cb54a2ab568f5595c586070708',
      authKey:
          '4e01ca008eb4f84b8cee1b84b3abfaeb4f2c7fb41d2c8ad0f4fe89d74e6f0fc5',
      randomizedPwd:
          'c741d0a042e653ee4ccf24648aee4e3b4c500cc28feb3a72eea0f24f69006693',
      envelope:
          '2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4a83190f798f947d61d060cb102e5eeb9bd698bec5d1e1b6788860ec7c2d2e590121b0',
      handshakeSecret:
          '78bedd3ee950e1795ddeca4e0d4f4267a971ace52e6f876d9b2c8a349ec2be2a',
      serverMacKey:
          'c8e62b9aee6ae6e2199db70f16631a302e9269f27d5f6ef954572f8ca05f8d01',
      clientMacKey:
          '31e3581fcfbb7d6b10b5cf78399fb844ab7afe42cf94f8b72178a1618711bb25',
      oprfKey:
          'd153d662a1e7dd4383837aa7125685d2be6f8041472ecbfd610e46952a6a24f1',
    ),
    output: VectorOutput(
      registrationRequest:
          '037aa042e317344246ebb94c38fe9989e01f7265413ade1f7ffaa706a81f58cf19',
      registrationResponse:
          '03c0b3e621cadf1a56aa48305e3101efedb6248157708c7ba70af396fa62d29bf7025b95a6add1f2f3d038811b5ad3494bed73b1e2500d8dadec592d88406e25c2f2',
      registrationUpload:
          '030f9b896400f6efd57c69a41b05ffedc456f041cb54a2ab568f5595c5860707085e76cb3c849637cfd386d9cc762050a476a58da7c24b8a390844689d8d6482bd2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4a83190f798f947d61d060cb102e5eeb9bd698bec5d1e1b6788860ec7c2d2e590121b0',
      ke1:
          '0320fee3e9c08dfd30d00ce524cee6595d9bd7387629efa0cb9eba1ba82ec46513967fcded96ed46986e60fcbdf985232639f537377ca3fcf07ad489956b2e901903358b4eae039953116889466bfddeb40168e39ed83809fd5f0d5f2de9c5234398',
      ke2:
          '03f629c1a3a5a3dc83af63c52d3bd58bbd78d5054caee7731381e967a7c381fa20cb792f3657240ce5296dd5633e7333531009c11ee6ab46b6111f156d96a160b22c17f819537c821604229b8c07798c56f14b5104729a1336f153510f58ea921758f8a48613ec4ee3e5675dc8be14776c0bb6458bf0d3f76dd24af8b43b49c8fbfcb5229c0bbe3a37c440bdca76ce404b215ceb8842e95e81138416e161ea02c2648018e88ecfc53891529278c47239f8fe6f1be88972721898ef81cc0a76a0b5500242bc29993976185dacf6be815cbfa923aac80fad8b7f020c9d4f18e0b6867a1764573de6cf3b1b7737e7e56a181fe0ec8754940adce33c4712bd35e7e9e08e7c',
      ke3: 'd9108b70e4ff4955911162ed1cec6df65c880aad120bbf10fd7f32eea71b1a04',
      exportKey:
          '086cd26a64f469f2d22ab0b5f0c524b10321c4019018b004d0f8383c024059be',
      sessionKey:
          '36d1125dbf5ea45568e586645841efb6c5f53d357cdffb79edf1bb8db0b843a9',
    ),
  ),
  Vector(
    name: 'OPAQUE-3DH Real Test Vector 4',
    suite: Suite.sha256p256(mhf: MemoryHardFunction.identity()),
    context: '4f50415155452d504f43',
    input: VectorInput(
      clientIdentity: '616c696365',
      serverIdentity: '626f62',
      oprfSeed:
          '482123652ea37c7e4a0f9f1984ff1f2a310fe428d9de5819bf63b3942dbe09f9',
      credentialIdentifier: '31323334',
      password: '436f7272656374486f72736542617474657279537461706c65',
      envelopeNonce:
          '75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e4426e42',
      maskingNonce:
          '5947586f69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f21',
      serverPrivateKey:
          'c728ebf47b1c65594d77dab871872dba848bdf20ed725f0fa3b58e7d8f3eab2b',
      serverPublicKey:
          '029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed0905c9f104d909138bae',
      serverNonce:
          '581ac468101aee528cc6b69daac7a90de8837d49708e76310767cbe4af18594d',
      clientNonce:
          '46498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa5fadace60',
      serverKeyshare:
          '022aa8746ab4329d591296652d44f6dfb04470103311bacd7ad51060ef5abac41b',
      clientKeyshare:
          '02a9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b22d3add6a0e0c0',
      serverPrivateKeyshare:
          '48a5baa24274d5acc5e007a44f2147549ac8dd6755642638f1029631944beed4',
      clientPrivateKeyshare:
          '161e3aaa50f50e33344022969d17d9cf4c88b7a9eec4c36bf64de079abb6dc7b',
      blindRegistration:
          '9280e203ef27d9ef0d1d189bb3c02a66ef9a72d48cca6c1f9afc1fedea22567c',
      blindLogin:
          '4308682dc1bdab92ff91bb1a5fc5bc084223fe4369beddca3f1640a6645455ad',
    ),
    intermediate: VectorIntermediate(
      clientPublicKey:
          '03ce71710d0d366e44e4a7e92cb111fc41353d4244cac1ce4d8a622acaab9effc6',
      authKey:
          'b894fa35f63413029fcc70e80a0d1b59d1c90c3c255bfb11cf7b58fb136d2aee',
      randomizedPwd:
          '0588794becaf8f5fee7921cb467e4ce8b3c048e7b42d815ed306def278c231d3',
      envelope:
          '75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e4426e42cb65c94629db9811649cd4f3ff92e5d2c67f7486203ea5e471f2655f363f9f19',
      handshakeSecret:
          '8a2547abef351fc1f94fb19a886c2e5ca16aba3b2bfe0b4a8cc086dd47b62c08',
      serverMacKey:
          'fa7c99e15ca1036738b9b48799515be78e471a2d06c3c3920d6a3703d11c0360',
      clientMacKey:
          'd480fde6de5e91a08179d9780bf6db0d1b959ae2fa394c09acdc607b993410c2',
      oprfKey:
          'f14e1fc34ba1218bfd3f7373f036889bf4f35a8fbc9e8c9c07ccf2d238879d9c',
    ),
    output: VectorOutput(
      registrationRequest:
          '02baa002c856f4b0d49542dcb1391f240f836178702f835819fd221bcf9b6e9eec',
      registrationResponse:
          '03864f4590c09b4c4155f0cbb731c5aab554ab1bc930c328e7a58bd6227933d54f029a2c6097fbbcf3457fe3ff7d4ef8e89dab585a67dfed0905c9f104d909138bae',
      registrationUpload:
          '03ce71710d0d366e44e4a7e92cb111fc41353d4244cac1ce4d8a622acaab9effc66c5d2844e32ed930c56080fa523c15ec6d85f7db1bbd02c469214b31e27f6c5775c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e4426e42cb65c94629db9811649cd4f3ff92e5d2c67f7486203ea5e471f2655f363f9f19',
      ke1:
          '038469dadcb23317fa577317079c82bad1e20be41c783cd0ecad6bef3de1b16b1446498f95ec7986f0602019b3fbb646db87a2fdbc12176d4f7ab74fa5fadace6002a9f857ad3eabe09047049e8b8cee72feea2acb7fc487777c0b22d3add6a0e0c0',
      ke2:
          '036297ebd0b53dabaae6377cb1c3ba1bdd942a67a5ce019b363f26cd11ae3707ac5947586f69259e0708bdfab794f689eec14c7deb7edde68c81645156cf278f213084ce22d007db399a17af864b5ea826f4086f3d477ce236cacf7867de174692940b103b367ccb8b5aee6ef352079bf95c5961442cf400432de4d904815d1a8a20f64f3e8447b82c27f4c9b798769db0fb5ab8d29ea0ee54c1e371105388a7ae7c581ac468101aee528cc6b69daac7a90de8837d49708e76310767cbe4af18594d022aa8746ab4329d591296652d44f6dfb04470103311bacd7ad51060ef5abac41bfa6b8e732462d3de6bdb3ef3edcf4595b478a6704d578fde4eaf922e1c1e8504',
      ke3: 'cd11b70f1ed59d101ec20a73745d3d654c3772236ed2c365a730ef8ee51da6d2',
      exportKey:
          '8e1eb57bcde2d58d805b16fa045811679c68b0ec2817b9ac61786786a9032837',
      sessionKey:
          'b1f3da97388d6171719c3e2281e88da75b68d6945189f460db841cc692f7e164',
    ),
  ),
];
