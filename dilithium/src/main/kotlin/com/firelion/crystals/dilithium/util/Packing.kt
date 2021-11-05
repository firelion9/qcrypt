package com.firelion.crystals.dilithium.util

import com.firelion.crystals.dilithium.struct.ByteArrayView
import com.firelion.crystals.dilithium.struct.PolynomialVector
import com.firelion.crystals.dilithium.struct.copyTo
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.POLYNOMIAL_T0_PACKED_BYTES
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.POLYNOMIAL_T1_PACKED_BYTES
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.SEED_BYTES


/**
 * Packs public key (writes [publicKey] = ([rho], [t1])).
 */
internal fun packPublicKey(
    publicKey: ByteArrayView,
    rho: ByteArrayView,
    t1: PolynomialVector,
    params: DilithiumParams
) {
    val off = publicKey.offset

    rho.copyTo(publicKey, SEED_BYTES)
    publicKey += SEED_BYTES

    t1.polynomials.forEach {
        it.packT1(publicKey)
        publicKey += POLYNOMIAL_T1_PACKED_BYTES
    }

    publicKey.offset = off
}


/**
 * Unpacks public key (reads ([rho], [t1]) = [publicKey]).
 */
internal fun unpackPublicKey(
    rho: ByteArrayView,
    t1: PolynomialVector,
    publicKey: ByteArrayView,
    params: DilithiumParams
) {
    val off = publicKey.offset

    publicKey.copyTo(rho, SEED_BYTES)
    publicKey += SEED_BYTES

    t1.polynomials.forEach {
        it.unpackT1(publicKey)
        publicKey += POLYNOMIAL_T1_PACKED_BYTES
    }

    publicKey.offset = off
}

/**
 * Packs private key (writes [privateKey] = ([rho], [tr], [key], [t0], [s1], [s2])).
 */
internal fun packPrivateKey(
    privateKey: ByteArrayView,
    rho: ByteArrayView,
    tr: ByteArrayView,
    key: ByteArrayView,
    t0: PolynomialVector,
    s1: PolynomialVector,
    s2: PolynomialVector,
    params: DilithiumParams
) {
    val off = privateKey.offset

    rho.copyTo(privateKey, SEED_BYTES)
    privateKey += SEED_BYTES

    key.copyTo(privateKey, SEED_BYTES)
    privateKey += SEED_BYTES

    tr.copyTo(privateKey, SEED_BYTES)
    privateKey += SEED_BYTES

    s1.polynomials.forEach {
        it.packEta(privateKey, params)
        privateKey += params.POLYNOMIAL_ETA_PACKED_BYTES
    }

    s2.polynomials.forEach {
        it.packEta(privateKey, params)
        privateKey += params.POLYNOMIAL_ETA_PACKED_BYTES
    }

    t0.polynomials.forEach {
        it.packT0(privateKey)
        privateKey += POLYNOMIAL_T0_PACKED_BYTES
    }

    privateKey.offset = off
}

/**
 * Unpacks private key (reads ([rho], [tr], [key], [t0], [s1], [s2]) = [privateKey]).
 */
internal fun unpackPrivateKey(
    rho: ByteArrayView,
    tr: ByteArrayView,
    key: ByteArrayView,
    t0: PolynomialVector,
    s1: PolynomialVector,
    s2: PolynomialVector,
    privateKey: ByteArrayView,
    params: DilithiumParams
) {
    val off = privateKey.offset

    privateKey.copyTo(rho, SEED_BYTES)
    privateKey += SEED_BYTES

    privateKey.copyTo(key, SEED_BYTES)
    privateKey += SEED_BYTES

    privateKey.copyTo(tr, SEED_BYTES)
    privateKey += SEED_BYTES

    s1.polynomials.forEach {
        it.unpackEta(privateKey, params)
        privateKey += params.POLYNOMIAL_ETA_PACKED_BYTES
    }

    s2.polynomials.forEach {
        it.unpackEta(privateKey, params)
        privateKey += params.POLYNOMIAL_ETA_PACKED_BYTES
    }

    t0.polynomials.forEach {
        it.unpackT0(privateKey)
        privateKey += POLYNOMIAL_T0_PACKED_BYTES
    }

    privateKey.offset = off
}

/**
 * Packs signature (writes [signature] = ([c], [z], [h])).
 */
internal fun packSignature(
    signature: ByteArrayView,
    c: ByteArrayView,
    z: PolynomialVector,
    h: PolynomialVector,
    params: DilithiumParams
) {
    val off = signature.offset

    c.copyTo(signature, SEED_BYTES)
    signature += SEED_BYTES

    z.polynomials.forEach {
        it.packZ(signature, params)
        signature += params.POLYNOMIAL_Z_PACKED_BYTES
    }

    // h encoding
    signature.array.fill(0, signature.offset, signature.offset + params.OMEGA + params.K)

    var count = 0
    h.polynomials.forEachIndexed { polyIdx, poly ->
        poly.coefficients.forEachIndexed { cfIdx, cf ->
            if (cf != 0) {
                signature[count++] = cfIdx.toByte()
            }
        }
        signature[params.OMEGA + polyIdx] = count.toByte()
    }

    signature.offset = off
}

/**
 * Unpacks signature (reads ([c], [z], [h]) = [signature]).
 *
 * Returns false in case of malformed signature; otherwise true.
 */
internal fun unpackSignature(
    c: ByteArrayView,
    z: PolynomialVector,
    h: PolynomialVector,
    signature: ByteArrayView,
    params: DilithiumParams
): Boolean {
    val off = signature.offset

    signature.copyTo(c, SEED_BYTES)
    signature += SEED_BYTES

    z.polynomials.forEach {
        it.unpackZ(signature, params)
        signature += params.POLYNOMIAL_Z_PACKED_BYTES
    }

    // h decoding
    var count = 0
    h.polynomials.forEachIndexed { polyIdx, poly ->
        poly.coefficients.fill(0)

        if (signature[params.OMEGA + polyIdx] < count || signature[params.OMEGA + polyIdx] > params.OMEGA) {
            signature.offset = off
            return false
        }

        (count until signature[params.OMEGA + polyIdx]).forEach { packedCfIdx ->
            /* Coefficients are ordered for strong unforgeability */
            if (packedCfIdx > count && signature[packedCfIdx].toIntUnsigned() <= signature[packedCfIdx - 1].toIntUnsigned()) {
                signature.offset = off
                return false
            }
            poly.coefficients[signature[packedCfIdx].toIntUnsigned()] = 1
        }
        count = signature[params.OMEGA + polyIdx].toIntUnsigned()
    }

    (count until params.OMEGA).forEach {
        if (signature[it] != 0.toByte()) {
            signature.offset = off
            return false
        }
    }
    signature.offset = off
    return true
}
