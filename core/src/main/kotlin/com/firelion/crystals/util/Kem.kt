package com.firelion.crystals.util

import com.firelion.crystals.util.KyberParams.Companion.KYBER_SYMMETRIC_BYTES

/**
 * Generates public and private key for CCA-secure Kyber key encapsulation mechanism.
 */
internal fun cryptoKemKeyPair(publicKey: ByteArray, privateKey: ByteArray, params: KyberParams) {
    indcpaKeyPair(publicKey, privateKey, params)
    (0 until params.KYBER_INDCPA_PUBLIC_KEY_BYTES).forEach { i ->
        privateKey[i + params.KYBER_INDCPA_PRIVATE_KEY_BYTES] = publicKey[i]
    }
    params.hashH(
        privateKey,
        params.KYBER_PRIVATE_KEY_BYTES - 2 * KYBER_SYMMETRIC_BYTES,
        publicKey,
        0,
        params.KYBER_PUBLIC_KEY_BYTES
    )
    /* Value z for pseudo-random output on reject */
    randomBytes(
        privateKey,
        params.KYBER_PRIVATE_KEY_BYTES - KYBER_SYMMETRIC_BYTES,
        KYBER_SYMMETRIC_BYTES,
        params
    )
}

/**
 * Generates cipher text and shared secret for given public key.
 */
internal fun cryptoKemEncrypt(
    publicKey: ByteArray,
    outCipherText: ByteArray,
    cipherTextOffset: Int,
    outSharedSecret: ByteArray,
    sharedSecretOffset: Int,
    params: KyberParams
) {
    val buf = ByteArray(2 * KYBER_SYMMETRIC_BYTES)
    /* Will contain key, coins */
    val kr = ByteArray(2 * KYBER_SYMMETRIC_BYTES)

    randomBytes(buf, 0, KYBER_SYMMETRIC_BYTES, params)
    /* Don't release system RNG output */
    params.hashH(buf, 0, buf, 0, KYBER_SYMMETRIC_BYTES)

    /* Multitarget countermeasure for coins + contributory KEM */
    params.hashH(buf, KYBER_SYMMETRIC_BYTES, publicKey, 0, params.KYBER_PUBLIC_KEY_BYTES)
    params.hashG(kr, 0, buf, 2 * KYBER_SYMMETRIC_BYTES)

    /* coins are in kr+KYBER_SYMMETRIC_BYTES */
    indcpaEncrypt(
        buf,
        publicKey,
        0,
        kr,
        KYBER_SYMMETRIC_BYTES,
        outCipherText,
        cipherTextOffset,
        params
    )

    /* overwrite coins in kr with H(c) */
    params.hashH(kr, KYBER_SYMMETRIC_BYTES, outCipherText, cipherTextOffset, params.KYBER_CIPHER_TEXT_BYTES)
    /* hash concatenation of pre-k and H(c) to k */
    params.kdf(outSharedSecret, sharedSecretOffset, kr, 2 * KYBER_SYMMETRIC_BYTES)
}

/**
 * Generates shared secret for given cipher text and private key.
 */
internal fun cryptoKemDecrypt(
    privateKey: ByteArray,
    sharedSecret: ByteArray,
    sharedSecretOffset: Int,
    cipherText: ByteArray,
    cipherTextOffset: Int,
    params: KyberParams
) {
    val buf = ByteArray(2 * KYBER_SYMMETRIC_BYTES)
    /* Will contain key, coins */
    val kr = ByteArray(2 * KYBER_SYMMETRIC_BYTES)
    val cmp = ByteArray(params.KYBER_CIPHER_TEXT_BYTES)

    indcpaDecrypt(cipherText, cipherTextOffset, privateKey, buf, 0, params)

    /* Multitarget countermeasure for coins + contributory KEM */
    (0 until KYBER_SYMMETRIC_BYTES).forEach { i ->
        buf[KYBER_SYMMETRIC_BYTES + i] = privateKey[params.KYBER_PRIVATE_KEY_BYTES - 2 * KYBER_SYMMETRIC_BYTES + i]
    }
    params.hashG(kr, 0, buf, 2 * KYBER_SYMMETRIC_BYTES)

    /* coins are in kr+KYBER_SYMMETRIC_BYTES */
    indcpaEncrypt(
        buf,
        privateKey,
        params.KYBER_INDCPA_PRIVATE_KEY_BYTES,
        kr,
        KYBER_SYMMETRIC_BYTES,
        cmp,
        0,
        params
    )

    val fail =
        cipherText.asList().subList(cipherTextOffset, cipherTextOffset + params.KYBER_CIPHER_TEXT_BYTES) != cmp.toList()

    /* overwrite coins in kr with H(c) */
    params.hashH(kr, KYBER_SYMMETRIC_BYTES, cipherText, cipherTextOffset, params.KYBER_CIPHER_TEXT_BYTES)

    /* Overwrite pre-k with z on re-encryption failure */
    if (fail) {
        System.arraycopy(
            privateKey,
            params.KYBER_PRIVATE_KEY_BYTES - KYBER_SYMMETRIC_BYTES,
            kr,
            0,
            KYBER_SYMMETRIC_BYTES
        )
    }

    /* hash concatenation of pre-k and H(c) to k */
    params.kdf(sharedSecret, sharedSecretOffset, kr, 2 * KYBER_SYMMETRIC_BYTES)
}
