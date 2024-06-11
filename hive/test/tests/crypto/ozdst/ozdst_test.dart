import 'dart:typed_data';

import 'package:hive/src/crypto/ozdst/gost_28147_engine.dart';
import 'package:hive/src/crypto/ozdst/key_parameter.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

import '../message.dart';

void main() {
  test('.encryptBlock()', () {
    var pcEngine = GOST28147Engine();
    pcEngine.init(true, KeyParameter(key));
    var out = Uint8List(message.length);
    for (var i = 0; i < message.length; i += pcEngine.BlockSize) {
      pcEngine.processBlock(message, i, out, i);
    }
    expect(message, out);
  });
}
