package wowchat.realm

// looks like they use https://github.com/jedisct1/libsodium

class HandshakeAscension {

  private val key_constant_1 = java.util.HexFormat.of.parseHex("3642af852369154cfa1145950880108280a4341c26a376431b741e2aae9c2948")
  private val key_constant_2 = java.util.HexFormat.of.parseHex("33ba3128ee614b5845e06b0dad176a9c79344dd7a7a1e2e8d8ad097da9b57f01")
  private val nonce_constant_2 = java.util.HexFormat.of.parseHex("9201008ecafa7d60e0acc81e")
  private val key_constant_3 = java.util.HexFormat.of.parseHex("66d52b01e006cd246f090025d6312c62d13e847c9805956a1c5a10364baa7d82")
  private val input_constant_4 = java.util.HexFormat.of.parseHex("e815739f8ec810721b93554ca2eac597e05f375261dd72ff30837df951c7a5ed")
  private val input_constant_5 = java.util.HexFormat.of.parseHex("26986c8a73d24bc41cf386bcb58492416fb579784e1957701a889d97b6550140")
  private val input_constant_6 = java.util.HexFormat.of.parseHex("4f4b")

  private val random_key_secret = generate_key()
  val key_public = calculate_key_public(random_key_secret)
  private val key_shared = calculate_key_shared(random_key_secret, key_constant_1)

  val random_nonce_1 = { val result = Array.fill[Byte](12)(0); scala.util.Random.nextBytes(result); result }

  val key_derived = derive_key(key_constant_3, key_shared, input_constant_4, 32)
  val key_session = derive_key(key_constant_3, key_shared, input_constant_5, 40)

  val proof_2 = calculate_proof(key_derived, input_constant_6)

  def encrypt_password(password: Array[Byte]): (Array[Byte], Array[Byte]) = {
    val encrypter = new org.bouncycastle.crypto.modes.ChaCha20Poly1305
    encrypter.init(
      true,
      new org.bouncycastle.crypto.params.AEADParameters(
        new org.bouncycastle.crypto.params.KeyParameter(key_derived),
        16 * 8,
        random_nonce_1
      )
    )
    val result = Array.fill[Byte](password.length + 16)(0)
    val processed = encrypter.processBytes(password, 0, password.length, result, 0)
    encrypter.doFinal(result, processed)
    (result.take(password.length), result.drop(password.length))
  }

  def encrypt_packet(data: Array[Byte], header: Array[Byte]) = {
    val encrypter = new org.bouncycastle.crypto.modes.ChaCha20Poly1305
    encrypter.init(
      true,
      new org.bouncycastle.crypto.params.AEADParameters(
        new org.bouncycastle.crypto.params.KeyParameter(key_constant_2),
        16 * 8,
        nonce_constant_2,
        header
      )
    )
    val result = Array.fill[Byte](data.length + 16)(0)
    //encrypter.processAADBytes(header, 0, header.length)
    val processed = encrypter.processBytes(data, 0, data.length, result, 0)
    encrypter.doFinal(result, processed)
    (result.take(data.length), result.drop(data.length))
  }

  private def generate_key(): Array[Byte] = {
    val result = Array.fill[Byte](32)(0)
    scala.util.Random.nextBytes(result)
    org.bouncycastle.math.ec.rfc7748.X25519.clampPrivateKey(result)
    result
  }

  private def calculate_key_public(key_private: Array[Byte]): Array[Byte] = {
    val result = Array.fill[Byte](32)(0)
    org.bouncycastle.math.ec.rfc7748.X25519.scalarMultBase(key_private, 0, result, 0)
    result
  }

  private def calculate_key_shared(key_1: Array[Byte], key_2: Array[Byte]): Array[Byte] = {
    val result = Array.fill[Byte](32)(0)
    org.bouncycastle.math.ec.rfc7748.X25519.scalarMult(key_1, 0, key_2, 0, result, 0)
    result
  }

  private def derive_key(key: Array[Byte], input_1: Array[Byte], input_2: Array[Byte], size: Int): Array[Byte] = {
    val algorithm = "HmacSHA256"
    val hasher_1 = javax.crypto.Mac.getInstance(algorithm)
    hasher_1.init(new javax.crypto.spec.SecretKeySpec(key, algorithm))
    val interim = hasher_1.doFinal(input_1)
    val hasher_2 = javax.crypto.Mac.getInstance(algorithm)
    hasher_2.init(new javax.crypto.spec.SecretKeySpec(interim, algorithm))
    hasher_2.update(input_2)
    val result = hasher_2.doFinal(Array[Byte](1))
    if (size == 32) {
      return result
    }
    {
      val hasher_2 = javax.crypto.Mac.getInstance(algorithm)
      hasher_2.init(new javax.crypto.spec.SecretKeySpec(interim, algorithm))
      hasher_2.update(result)
      hasher_2.update(input_2)
      val result_ = hasher_2.doFinal(Array[Byte](2))
      (result ++ result_).take(size)
    }
  }

  private def calculate_proof(key: Array[Byte], input_1: Array[Byte]): Array[Byte] = {
    val algorithm = "HmacSHA256"
    val hasher = javax.crypto.Mac.getInstance(algorithm)
    hasher.init(new javax.crypto.spec.SecretKeySpec(key, algorithm))
    hasher.doFinal(input_1)
  }
}
