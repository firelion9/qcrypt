@file:Suppress("PrivatePropertyName", "PropertyName")

package com.firelion.crystals.dilithium.util

import com.firelion.crystals.dilithium.digest.Shake
import com.firelion.crystals.dilithium.digest.Stream
import java.security.SecureRandom

// Type aliases for different parameter sets
typealias Dilithium2 = DilithiumParams.Dilithium2
typealias Dilithium3 = DilithiumParams.Dilithium3
typealias Dilithium5 = DilithiumParams.Dilithium5

/**
 * Represents a parameter set for Dilithium.
 *
 */
sealed class DilithiumParams(
    internal val K: Int,
    internal val L: Int,
    internal val ETA: Int,
    internal val TAU: Int,
    internal val GAMMA1: Int,
    internal val GAMMA2: Int,
    internal val OMEGA: Int,
    internal val RANDOMIZED_SIGNING: Boolean,
    internal val random: SecureRandom
) {
    internal val BETA = TAU * ETA

    internal val POLYNOMIAL_VECTOR_H_PACKED_BYTES = (OMEGA + K)

    internal val POLYNOMIAL_Z_PACKED_BYTES = when (GAMMA1) {
        1 shl 17 -> 576
        else -> 640
    }

    internal val POLYNOMIAL_W1_PACKED_BYTES = when (GAMMA2) {
        (DILITHIUM_Q - 1) / 88 -> 192
        else -> 128
    }

    internal val POLYNOMIAL_ETA_PACKED_BYTES = when (ETA) {
        2 -> 96
        else -> 128
    }

    internal val CRYPTO_PUBLIC_KEY_BYTES = SEED_BYTES + K * POLYNOMIAL_T1_PACKED_BYTES

    internal val CRYPTO_PRIVATE_KEY_BYTES =
        3 * SEED_BYTES + L * POLYNOMIAL_ETA_PACKED_BYTES + K * POLYNOMIAL_ETA_PACKED_BYTES + K * POLYNOMIAL_T0_PACKED_BYTES

    internal val SIGNATURE_BYTES = SEED_BYTES + L * POLYNOMIAL_Z_PACKED_BYTES + POLYNOMIAL_VECTOR_H_PACKED_BYTES

    internal val SHAKE128 = Shake(false)
    internal val SHAKE256 = Shake(true)

    internal val STREAM128 = Stream(false)
    internal val STREAM256 = Stream(true)

    companion object {

        internal const val N: Int = 256
        internal const val DILITHIUM_Q: Int = 8380417
        internal const val D: Int = 13

        internal const val SEED_BYTES: Int = 32
        internal const val CRH_BYTES: Int = 64

        internal const val POLYNOMIAL_T0_PACKED_BYTES = 416
        internal const val POLYNOMIAL_T1_PACKED_BYTES = 320

        /**
         * [DILITHIUM_Q]^(-1) mod 2^32
         */
        internal const val Q_INV: Int = 58728449

        internal const val STREAM128_BLOCK_BYTES = 168
        internal const val STREAM256_BLOCK_BYTES = 136

    }

    class Dilithium2(randomizedSigning: Boolean, random: SecureRandom) : DilithiumParams(
        TAU = 39,
        GAMMA1 = 1 shl 17,
        GAMMA2 = (DILITHIUM_Q - 1) / 88,
        K = 4,
        L = 4,
        ETA = 2,
        OMEGA = 80,
        RANDOMIZED_SIGNING = randomizedSigning,
        random = random
    )

    class Dilithium3(randomizedSigning: Boolean, random: SecureRandom) : DilithiumParams(
        TAU = 49,
        GAMMA1 = 1 shl 19,
        GAMMA2 = (DILITHIUM_Q - 1) / 32,
        K = 6,
        L = 5,
        ETA = 4,
        OMEGA = 55,
        RANDOMIZED_SIGNING = randomizedSigning,
        random = random
    )

    class Dilithium5(randomizedSigning: Boolean, random: SecureRandom) : DilithiumParams(
        TAU = 60,
        GAMMA1 = 1 shl 19,
        GAMMA2 = (DILITHIUM_Q - 1) / 32,
        K = 8,
        L = 7,
        ETA = 2,
        OMEGA = 75,
        RANDOMIZED_SIGNING = randomizedSigning,
        random = random
    )
}