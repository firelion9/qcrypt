package com.firelion.crystals.kyber.util

import com.firelion.crystals.kyber.struct.*
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_N
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_Q
import com.firelion.crystals.kyber.util.KyberParams.Companion.KYBER_SYMMETRIC_BYTES

/**
 * Serialize the public key as concatenation of the serialized
 * vector of polynomials [key]
 * and the public [seed] used to generate the matrix A.
 */
internal fun packPublicKey(key: PolynomialVector, seed: ByteArray, out: ByteArray, params: KyberParams) {
    key.toBytes(out)
    System.arraycopy(seed, 0, out, params.KYBER_POLYNOMIAL_VECTOR_BYTES, KYBER_SYMMETRIC_BYTES)
}

/**
 * De-serialize public key from a byte array;
 *              approximate inverse of [packPublicKey]
 */
internal fun unpackPublicKey(
    bytes: ByteArray,
    bytesOffset: Int,
    key: PolynomialVector,
    seed: ByteArray,
    params: KyberParams
) {
    PolynomialVector.fromBytes(bytes, bytesOffset, key)
    (0 until KYBER_SYMMETRIC_BYTES).forEach { i ->
        seed[i] = bytes[bytesOffset + params.KYBER_POLYNOMIAL_VECTOR_BYTES + i]
    }
}

/**
 * Serialize the private key
 */
internal fun packPrivateKey(privateKey: PolynomialVector, out: ByteArray) {
    privateKey.toBytes(out)
}

/**
 * De-serialize the secret key; inverse of [packPrivateKey]
 */
internal fun unpackPrivateKey(bytes: ByteArray, out: PolynomialVector) {
    PolynomialVector.fromBytes(bytes, 0, out)
}

/**
 * Serialize the cipher text as concatenation of the compressed and serialized
 * vector of polynomials [CipherText.b] and the compressed and serialized polynomial [CipherText.v]
 */
internal fun packCipherText(cipherText: CipherText, out: ByteArray, outOffset: Int, params: KyberParams) {
    cipherText.b.compress(out, outOffset, params)
    cipherText.v.compress(out, outOffset + params.KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES, params)
}

/**
 * De-serialize and decompress cipher text from a byte array.
 * Approximate inverse of [packCipherText].
 */
internal fun unpackCipherText(bytes: ByteArray, bytesOffset: Int, out: CipherText, params: KyberParams) {
    PolynomialVector.decompress(bytes, bytesOffset, out.b, params)
    Polynomial.decompress(
        bytes,
        bytesOffset + params.KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES,
        out.v,
        params
    )
}

/**
 * Run rejection sampling on uniform random bytes to generate uniform random integers mod q
 */
internal fun rejectUniform(
    input: ByteArray,
    inputOffset: Int,
    inputLen: Int,
    out: IntArray,
    outOffset: Int,
    outLen: Int
): Int {
    var outCount = 0
    var inOffset = inputOffset

    while (outCount < outLen && inOffset + 3 <= inputLen + inputOffset) {
        val val0 = ((input[inOffset++] ushr 0).toIntUnsigned() or (input[inOffset].toIntUnsigned() shl 8)) and 0xfff
        val val1 = ((input[inOffset++] ushr 4).toIntUnsigned() or (input[inOffset].toIntUnsigned() shl 4)) and 0xfff
        inOffset++

        if (val0 < KYBER_Q) out[outOffset + outCount++] = val0
        if (outCount < outLen && val1 < KYBER_Q) out[outOffset + outCount++] = val1
    }

    return outCount
}


private const val GEN_MATRIX_BLOCKS_COUNT =
    ((12 * KYBER_N / 8 * (1 shl 12) / KYBER_Q + XOF_BLOCK_BYTES) / XOF_BLOCK_BYTES)

/**
 * Deterministically generate matrix A (or the transpose of A) from a seed.
 * Entries of the matrix are polynomials that look uniformly random.
 * Performs rejection sampling on output of a XOF.
 */
internal fun genMatrix(out: Array<PolynomialVector>, seed: ByteArray, transposed: Boolean, params: KyberParams) {
    val buf = ByteArray(GEN_MATRIX_BLOCKS_COUNT * XOF_BLOCK_BYTES + 2)
    val xof = Xof()

    (0 until params.KYBER_K).forEach { i ->
        (0 until params.KYBER_K).forEach { j ->
            if (transposed) xof.kyberAbsorb(seed, i.toByte(), j.toByte())
            else xof.kyberAbsorb(seed, j.toByte(), i.toByte())

            xof.squeezeBlocks(buf, 0, GEN_MATRIX_BLOCKS_COUNT)
            var bufLen = GEN_MATRIX_BLOCKS_COUNT * XOF_BLOCK_BYTES
            var count = rejectUniform(buf, 0, bufLen, out[i].polynomials[j].coefficients, 0, KYBER_N)

            while (count < KYBER_N) {
                val off = bufLen % 3
                (0 until off).forEach { k -> buf[k] = buf[bufLen - off + k] }

                xof.squeezeBlocks(buf, off, 1)
                bufLen = off + XOF_BLOCK_BYTES
                count += rejectUniform(buf, 0, bufLen, out[i].polynomials[j].coefficients, count, KYBER_N - count)
            }
        }
    }
}

internal fun genA(out: Array<PolynomialVector>, seed: ByteArray, params: KyberParams) =
    genMatrix(out, seed, false, params)

internal fun genAT(out: Array<PolynomialVector>, seed: ByteArray, params: KyberParams) =
    genMatrix(out, seed, true, params)

/**
 * Generates public and private key for the CPA-secure public-key encryption scheme underlying Kyber
 */
internal fun indcpaKeyPair(publicKey: ByteArray, privateKey: ByteArray, params: KyberParams) {
    val buf = ByteArray(2 * KYBER_SYMMETRIC_BYTES)
    var nonce: Byte = 0
    val a = Array(params.KYBER_K) { PolynomialVector(params) }
    val e = PolynomialVector(params)
    val publicKeyVec = PolynomialVector(params)
    val privateKeyVec = PolynomialVector(params)

    randomBytes(buf, 0, KYBER_SYMMETRIC_BYTES, params)
    params.hashG(buf, 0, buf, KYBER_SYMMETRIC_BYTES)

    genA(a, buf, params)

    (0 until params.KYBER_K).forEach { i ->
        Polynomial.getNoiseEta1(buf, KYBER_SYMMETRIC_BYTES, nonce++, privateKeyVec.polynomials[i], params)
    }
    privateKeyVec.ntt()

    (0 until params.KYBER_K).forEach { i ->
        Polynomial.getNoiseEta1(buf, KYBER_SYMMETRIC_BYTES, nonce++, e.polynomials[i], params)
    }
    e.ntt()

    // matrix-vector multiplication
    (0 until params.KYBER_K).forEach { i ->

        a[i].baseMulAccumulatedMontgomery(privateKeyVec, publicKeyVec.polynomials[i])
        publicKeyVec.polynomials[i].toMont()
    }

    publicKeyVec.add(e, publicKeyVec)
    publicKeyVec.reduce()

    packPrivateKey(privateKeyVec, privateKey)
    packPublicKey(publicKeyVec, buf, publicKey, params)
}

/**
 * Encryption function of the CPA-secure public-key encryption scheme underlying Kyber.
 */
internal fun indcpaEncrypt(
    message: ByteArray,
    publicKey: ByteArray,
    publicKeyOffset: Int,
    coins: ByteArray,
    coinsOffset: Int,
    outCipherText: ByteArray,
    cipherTextOffset: Int,
    params: KyberParams
) {
    val key = PolynomialVector(params)
    val seed = ByteArray(KYBER_SYMMETRIC_BYTES)

    var nonce: Byte = 0
    val sp = PolynomialVector(params)
    val ep = PolynomialVector(params)
    val at = Array(params.KYBER_K) { PolynomialVector(params) }
    val b = PolynomialVector(params)

    val v = Polynomial()
    val k = Polynomial()
    val epp = Polynomial()

    unpackPublicKey(publicKey, publicKeyOffset, key, seed, params)
    Polynomial.fromMsg(message, k)
    genAT(at, seed, params)

    (0 until params.KYBER_K).forEach { i ->
        Polynomial.getNoiseEta1(coins, coinsOffset, nonce++, sp.polynomials[i], params)
    }
    sp.ntt()

    (0 until params.KYBER_K).forEach { i ->
        Polynomial.getNoiseEta2(coins, coinsOffset, nonce++, ep.polynomials[i], params)
    }

    Polynomial.getNoiseEta2(coins, coinsOffset, nonce++, epp, params)

    // matrix-vector multiplication
    (0 until params.KYBER_K).forEach { i ->
        at[i].baseMulAccumulatedMontgomery(sp, b.polynomials[i])
    }
    key.baseMulAccumulatedMontgomery(sp, v)
    b.inverseNttToMont()
    v.inverseNttToMont()

    b.add(ep, b)
    v.add(epp, v)
    v.add(k, v)

    b.reduce()
    v.reduce()

    packCipherText(CipherText(b, v), outCipherText, cipherTextOffset, params)
}

/**
 * Decryption function of the CPA-secure public-key encryption scheme underlying Kyber.
 */
internal fun indcpaDecrypt(
    cipherText: ByteArray,
    cipherTextOffset: Int,
    privateKey: ByteArray,
    out: ByteArray,
    outOffset: Int,
    params: KyberParams
) {
    val key = PolynomialVector(params)
    val text = CipherText(params)

    unpackCipherText(cipherText, cipherTextOffset, text, params)
    unpackPrivateKey(privateKey, key)

    val mp = Polynomial()

    text.b.ntt()
    key.baseMulAccumulatedMontgomery(text.b, mp)
    mp.inverseNttToMont()

    text.v.sub(mp, mp)
    mp.reduce()

    mp.toMsg(out, outOffset)
}
