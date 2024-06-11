part of hive;

/// Default encryption algorithm. Uses AES256 CBC with PKCS7 padding.
class HiveOzdstCipher implements HiveCipher {
  static final _ivRandom = Random.secure();

  late final int _keyCrc;
  late final List<int> _keyBytes;

  final GOST28147Engine _gost28147engine = GOST28147Engine();

  /// Create a cipher with the given [key].
  HiveOzdstCipher(List<int> key) {
    if (key.length != 32 || key.any((it) => it < 0 || it > 255)) {
      throw ArgumentError('The encryption key has to be a 32 byte (256 bit) array.');
    }

    var keyBytes = Uint8List.fromList(key);
    _keyCrc = Crc32.compute(sha256.convert(keyBytes).bytes as Uint8List);
    _keyBytes = key;
  }

  @override
  int calculateKeyCrc() => _keyCrc;

  @override
  FutureOr<int> decrypt(Uint8List inp, int inpOff, int inpLength, Uint8List out, int outOff) {
    // var iv = inp.view(inpOff, 16);
    //
    // return _cipher.decrypt(iv, inp, inpOff + 16, inpLength - 16, out, 0);
    Ozdst.decrypt(inp, out, _keyBytes);
    return 1;
  }

  /// Generates a random initialization vector (internal)
  @visibleForTesting
  Uint8List generateIv() => _ivRandom.nextBytes(16);

  @override
  FutureOr<int> encrypt(Uint8List inp, int inpOff, int inpLength, Uint8List out, int outOff) {
    // var iv = generateIv();
    // out.setAll(outOff, iv);
    //
    // var len = _cipher.encrypt(iv, inp, 0, inpLength, out, outOff + 16);
    //
    Ozdst.encrypt(inp, out, _keyBytes);
    return 1;
  }

  @override
  int maxEncryptedSize(Uint8List inp) {
    return inp.length + 32; // 16 IV + 16 extra for padding
  }
}
