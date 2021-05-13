@file:Suppress("PrivatePropertyName", "PropertyName")

package com.firelion.crystals.util

import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import java.security.SecureRandom

// Type aliases for different parameter sets
typealias Kyber1024 = KyberParams.KyberParamsNormal.Kyber1024
typealias Kyber768 = KyberParams.KyberParamsNormal.Kyber768
typealias Kyber512 = KyberParams.KyberParamsNormal.Kyber512

/**
 * Represents a parameter set for Kyber.
 *
 * @see [Kyber1024], [Kyber768], [Kyber512]
 */
sealed class KyberParams(val KYBER_K: Int, val random: SecureRandom) {
    sealed class KyberParamsNormal(k: Int, random: SecureRandom) : KyberParams(k, random) {
        class Kyber1024(random: SecureRandom) : KyberParamsNormal(4, random)
        class Kyber768(random: SecureRandom) : KyberParamsNormal(3, random)
        class Kyber512(random: SecureRandom) : KyberParamsNormal(2, random)

        private val SHAKE256 = SHAKEDigest(256)
        override fun prf(out: ByteArray, offset: Int, size: Int, key: ByteArray, keyOffset: Int, nonce: Byte) {
            SHAKE256.update(key, keyOffset, KYBER_SYMMETRIC_BYTES)
            SHAKE256.update(nonce)
            SHAKE256.doFinal(out, offset, size)
        }

        private val SHA256 = SHA3Digest(256)
        override fun hashH(output: ByteArray, outputOffset: Int, input: ByteArray, inputOffset: Int, length: Int) {
            SHA256.update(input, inputOffset, length)
            SHA256.doFinal(output, outputOffset)
        }

        private val SHA512 = SHA3Digest(512)
        override fun hashG(output: ByteArray, outputOffset: Int, input: ByteArray, length: Int) {
            SHA512.update(input, 0, length)
            SHA512.doFinal(output, outputOffset)
        }

        override fun kdf(output: ByteArray, outputOffset: Int, input: ByteArray, length: Int) {
            SHAKE256.update(input, 0, length)
            SHAKE256.doFinal(output, outputOffset)
        }
    }

    internal val KYBER_POLYNOMIAL_VECTOR_BYTES: Int = (KYBER_K * KYBER_POLYNOMIAL_BYTES)

    internal val KYBER_ETA1: Int = when (KYBER_K) {
        2 -> 3
        3, 4 -> 2
        else -> -1
    }
    internal val KYBER_POLYNOMIAL_COMPRESSED_BYTES = when (KYBER_K) {
        2, 3 -> 128
        4 -> 160
        else -> -1
    }
    internal val KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES = KYBER_K * when (KYBER_K) {
        2, 3 -> 320
        4 -> 352
        else -> -1
    }

    internal val KYBER_INDCPA_PUBLIC_KEY_BYTES = KYBER_POLYNOMIAL_VECTOR_BYTES + KYBER_SYMMETRIC_BYTES
    internal val KYBER_INDCPA_PRIVATE_KEY_BYTES = KYBER_POLYNOMIAL_VECTOR_BYTES
    internal val KYBER_INDCPA_BYTES = KYBER_POLYNOMIAL_VECTOR_COMPRESSED_BYTES + KYBER_POLYNOMIAL_COMPRESSED_BYTES

    val KYBER_PUBLIC_KEY_BYTES = KYBER_INDCPA_PUBLIC_KEY_BYTES

    /* 32 bytes of additional space to save H(pk) */
    val KYBER_PRIVATE_KEY_BYTES =
        KYBER_INDCPA_PRIVATE_KEY_BYTES + KYBER_INDCPA_PUBLIC_KEY_BYTES + 2 * KYBER_SYMMETRIC_BYTES
    internal val KYBER_CIPHER_TEXT_BYTES = KYBER_INDCPA_BYTES

    val KEX_UAKE_SEND_A_BYTES = KYBER_PUBLIC_KEY_BYTES + KYBER_CIPHER_TEXT_BYTES
    val KEX_UAKE_SEND_B_BYTES = KYBER_CIPHER_TEXT_BYTES

    val KEX_AKE_SEND_A_BYTES = KYBER_PUBLIC_KEY_BYTES + KYBER_CIPHER_TEXT_BYTES
    val KEX_AKE_SEND_B_BYTES = 2 * KYBER_CIPHER_TEXT_BYTES

    companion object {
        internal const val KYBER_N: Int = 256
        internal const val KYBER_Q: Int = 3329

        /**
         * [KYBER_Q]^(-1) mod 2^16
         */
        internal const val Q_INV: Int = -3327

        /** Size in bytes of hashes, and seeds */
        const val KYBER_SYMMETRIC_BYTES: Int = 32

        /** Size in bytes of shared key */
        internal const val KYBER_SHARED_SECRET_BYTES: Int = 32
        internal const val KYBER_POLYNOMIAL_BYTES: Int = 384
        internal const val KYBER_ETA2 = 2
        internal const val KYBER_INDCPA_MESSAGE_BYTES = KYBER_SYMMETRIC_BYTES
    }

    abstract fun prf(out: ByteArray, offset: Int, size: Int, key: ByteArray, keyOffset: Int, nonce: Byte)
    abstract fun hashH(output: ByteArray, outputOffset: Int, input: ByteArray, inputOffset: Int, length: Int)
    abstract fun hashG(output: ByteArray, outputOffset: Int, input: ByteArray, length: Int)
    abstract fun kdf(output: ByteArray, outputOffset: Int, input: ByteArray, length: Int)
}