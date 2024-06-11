import 'dart:typed_data';

import 'package:hive/src/crypto/ozdst/cipher_parameters.dart';
import 'package:hive/src/crypto/ozdst/gost_28147_engine.dart';
import 'package:hive/src/crypto/ozdst/key_parameter.dart';
import 'package:hive/src/crypto/ozdst/parameters_with_sbox.dart';

class Ozdst {
  static Uint8List encrypt(List<int> messageBytes, Uint8List outputData, List<int> keyBytes,
      {String sBoxName = "D-A"}) {
    final GOST28147Engine engine = GOST28147Engine();
    final List<int> sBox = GOST28147Engine.getSBox(sBoxName);
    final ParametersWithSBox keyParameter = ParametersWithSBox(KeyParameter(keyBytes), sBox);
    engine.init(true, keyParameter);

    final int padSize = engine.BlockSize - messageBytes.length % engine.BlockSize;
    final int messageBytesLength = messageBytes.length;

    final Uint8List input = Uint8List(messageBytesLength + padSize)
      ..setRange(0, messageBytesLength, messageBytes);

    for (int i = 0; i < padSize; i++) {
      input[messageBytesLength + i] = padSize;
    }

    for (int i = 0; i < input.length; i += engine.BlockSize) {
      engine.processBlock(input, i, outputData, i);
    }

    return outputData;
  }

  static List<int> decrypt(List<int> encBytes, Uint8List outBuf, List<int> keyBytes,
      {String sBoxName = "D-A"}) {
    final int messageBytesLength = encBytes.length;
    final List<int> sBox = GOST28147Engine.getSBox(sBoxName);

    final CipherParameters parameters = ParametersWithSBox(KeyParameter(keyBytes), sBox);

    final GOST28147Engine engine = GOST28147Engine();
    engine.init(false, parameters);

    final int bs = engine.BlockSize;

    for (int i = 0; i < messageBytesLength ~/ bs; i++) {
      engine.processBlock(encBytes, i * bs, outBuf, i * bs);
    }

    int padSize = outBuf[outBuf.length - 1];
    if (padSize < 0 || padSize > bs) {
      // throw Exception("invalid padding size");
    }

    final Uint8List out = Uint8List.sublistView(outBuf, 0, outBuf.length - padSize);

    if (padSize == 1) {
      return out;
    }

    int p = outBuf.length;
    while (p > outBuf.length - padSize + 1) {
      p--;
      if (outBuf[p] - 1 != outBuf[p - 1]) {
        // throw Exception("invalid padding value");
      }
    }

    return out;
  }
}
