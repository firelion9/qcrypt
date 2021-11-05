package com.firelion.crystals.dilithium.util

import com.firelion.crystals.dilithium.struct.ByteArrayView
import com.firelion.crystals.dilithium.struct.Polynomial
import com.firelion.crystals.dilithium.struct.PolynomialVector
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.CRH_BYTES
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.SEED_BYTES

/**
 * Generates a new dilithium key pair and writes it to [publicKey] and [privateKey].
 **/
fun dilithiumKeypair(publicKey: ByteArray, privateKey: ByteArray, params: DilithiumParams) {
    val seedBuffer = ByteArrayView(2 * SEED_BYTES + CRH_BYTES)
    val tr = ByteArray(SEED_BYTES)
    val mat = Array(params.K) { PolynomialVector(params.L) }

    /* Get randomness for rho, rhoPrime and key */
    randomBytes(seedBuffer, SEED_BYTES, params)
    with(params.SHAKE256) {
        update(seedBuffer.array, 0, SEED_BYTES)
        doFinal(seedBuffer.array, 0, 2 * SEED_BYTES + CRH_BYTES)
    }

    val rho = seedBuffer
    val rhoPrime = ByteArrayView(seedBuffer.array, SEED_BYTES)
    val key = ByteArrayView(seedBuffer.array, SEED_BYTES + CRH_BYTES)

    /* Expand matrix */
    PolynomialVector.expandMatrix(mat, rho, params)

    /* Sample short vectors s1 and s2 */
    val s1 = PolynomialVector(params.L)
    s1.uniformEta(rhoPrime, 0, params)
    val s2 = PolynomialVector(params.K)
    s2.uniformEta(rhoPrime, params.L.toShort(), params)

    /* Matrix-vector multiplication */
    val s1hat = s1.deepCopy()
    s1hat.ntt()

    val t1 = PolynomialVector(params.K)
    val t0 = PolynomialVector(params.K)

    t1.matrixPointwiseMontgomery(mat, s1hat)
    t1.reduce()
    t1.inverseNttToMont()

    /* Add error vector s2 */
    t1.add(s2, t1)

    /* Extract t1 and write public key */
    t1.caddq()
    t1.power2Round(t0, t1)
    packPublicKey(ByteArrayView(publicKey), rho, t1, params)

    /* Compute H(rho, t1) and write secret key */
    with(params.SHAKE256) {
        update(publicKey, 0, params.CRYPTO_PUBLIC_KEY_BYTES)
        doFinal(tr, 0, SEED_BYTES)
    }
    packPrivateKey(ByteArrayView(privateKey), rho, ByteArrayView(tr), key, t0, s1, s2, params)
}

/**
 * Signs [message] (of length [messageLength]) with [privateKey] and writes the result to [signature].
 *
 * Returns written [signature] length ([DilithiumParams.SIGNATURE_BYTES] of [params]).
 **/
internal fun signature(
    signature: ByteArrayView,
    message: ByteArrayView,
    messageLength: Int,
    privateKey: ByteArray, params: DilithiumParams
): Int {
    val seedbuf = ByteArrayView(3 * SEED_BYTES + 2 * CRH_BYTES)
    var nonce = 0

    val mat = Array(params.K) { PolynomialVector(params.L) }

    val s1 = PolynomialVector(params.L)
    val s2 = PolynomialVector(params.K)
    val t0 = PolynomialVector(params.K)

    val rho = seedbuf;
    val tr = ByteArrayView(rho.array, SEED_BYTES)
    val key = ByteArrayView(rho.array, 2 * SEED_BYTES)
    val mu = ByteArrayView(rho.array, 3 * SEED_BYTES)
    val rhoPrime = ByteArrayView(rho.array, 3 * SEED_BYTES + CRH_BYTES)


    unpackPrivateKey(rho, tr, key, t0, s1, s2, ByteArrayView(privateKey), params)

    with(params.SHAKE256) {
        absorb(tr, SEED_BYTES)
        absorb(message, messageLength)
        doFinal(mu.array, mu.offset, CRH_BYTES)
    }

    if (params.RANDOMIZED_SIGNING)
        randomBytes(rhoPrime, CRH_BYTES, params)
    else
        with(params.SHAKE256) {
            update(key.array, key.offset, SEED_BYTES + CRH_BYTES)
            doFinal(rhoPrime.array, rhoPrime.offset, CRH_BYTES)
        }

    /* Expand matrix and transform vectors */
    PolynomialVector.expandMatrix(mat, rho, params)
    s1.ntt()
    s2.ntt()
    t0.ntt()

    val y = PolynomialVector(params.L)
    val w1 = PolynomialVector(params.K)
    val w0 = PolynomialVector(params.K)
    val h = PolynomialVector(params.K)
    val cp = Polynomial()

    while (true) {
        /* Sample intermediate vector y */
        y.uniformGamma1(rhoPrime, nonce++.toShort(), params)
        /* Matrix-vector multiplication */
        val z = y.deepCopy()
        z.ntt()
        w1.matrixPointwiseMontgomery(mat, z)
        w1.reduce()
        w1.inverseNttToMont()

        /* Decompose w and call the random oracle */
        w1.caddq()
        w1.decompose(w0, w1, params)
        w1.packW1(signature, params)

        with(params.SHAKE256) {
            absorb(mu, CRH_BYTES)
            absorb(signature, params.K * params.POLYNOMIAL_W1_PACKED_BYTES)
            doFinal(signature.array, signature.offset, SEED_BYTES)
        }
        cp.challenge(signature, params)
        cp.ntt()

        /* Compute z, reject if it reveals secret */
        z.pointwisePolynomialMontgomery(cp, s1)
        z.inverseNttToMont()
        z.add(y, z)
        z.reduce()

        if (z.checkNorm(params.GAMMA1 - params.BETA)) continue

        /* Check that subtracting cs2 does not change high bits of w and low bits
         * do not reveal secret information */
        h.pointwisePolynomialMontgomery(cp, s2)
        h.inverseNttToMont()
        w0.sub(h, w0)
        w0.reduce()
        if (w0.checkNorm(params.GAMMA2 - params.BETA)) continue

        /* Compute hints for w1 */
        h.pointwisePolynomialMontgomery(cp, t0)
        h.inverseNttToMont()
        h.reduce()
        if (h.checkNorm(params.GAMMA2)) continue

        w0.add(h, w0)
        val n = h.makeHint(w0, w1, params)
        if (n > params.OMEGA) continue

        /* Write signature */
        packSignature(signature, signature, z, h, params)
        return params.SIGNATURE_BYTES
    }
}

/**
 * Signs [message] (of length [messageLength]) with [privateKey].
 * Writes the original [message] and the signature to [signedMessage].
 *
 * Returns written [signedMessage] length ([DilithiumParams.SIGNATURE_BYTES] of [params] + [messageLength]).
 **/
fun dilithiumSign(
    signedMessage: ByteArray,
    message: ByteArray,
    messageLength: Int,
    privateKey: ByteArray,
    params: DilithiumParams
): Int {
    System.arraycopy(message, 0, signedMessage, params.SIGNATURE_BYTES, messageLength)

    val len = signature(
        ByteArrayView(signedMessage),
        ByteArrayView(signedMessage, params.SIGNATURE_BYTES),
        messageLength,
        privateKey,
        params
    )
    return len + messageLength
}

/**
 * Verifies [signature] (with length [signatureLength])
 * of [message] (with length [messageLength]) using [publicKey].
 *
 * Returns `true` if signature is correct and `false` otherwise.
 **/
internal fun verifySignature(
    signature: ByteArrayView,
    signatureLength: Int,
    message: ByteArrayView,
    messageLength: Int,
    publicKey: ByteArray,
    params: DilithiumParams
): Boolean {
    val buffer = ByteArrayView(params.K * params.POLYNOMIAL_W1_PACKED_BYTES)

    if (signatureLength != params.SIGNATURE_BYTES) return false

    val arrays = ByteArrayView(3 * SEED_BYTES + CRH_BYTES)

    val rho = arrays
    val t1 = PolynomialVector(params.K)

    unpackPublicKey(rho, t1, ByteArrayView(publicKey), params)

    val c = ByteArrayView(arrays.array, SEED_BYTES)
    val z = PolynomialVector(params.L)
    val h = PolynomialVector(params.K)

    if (!unpackSignature(c, z, h, signature, params)) return false

    if (z.checkNorm(params.GAMMA1 - params.BETA)) return false

    val mu = ByteArrayView(arrays.array, 2 * SEED_BYTES)

    /* Compute CRH(H(rho, t1), msg) */
    with(params.SHAKE256) {
        update(publicKey, 0, params.CRYPTO_PUBLIC_KEY_BYTES)
        doFinal(mu.array, mu.offset, SEED_BYTES)

        absorb(mu, SEED_BYTES)
        absorb(message, messageLength)
        doFinal(mu.array, mu.offset, CRH_BYTES)
    }

    /* Matrix-vector multiplication; compute Az - c2^dt1 */

    val cp = Polynomial()
    val mat = Array(params.K) { PolynomialVector(params.L) }
    val w1 = PolynomialVector(params.K)

    cp.challenge(c, params)
    PolynomialVector.expandMatrix(mat, rho, params)

    z.ntt()
    w1.matrixPointwiseMontgomery(mat, z)

    cp.ntt()
    t1.shiftLeft()
    t1.ntt()
    t1.pointwisePolynomialMontgomery(cp, t1)

    w1.sub(t1, w1)
    w1.reduce()
    w1.inverseNttToMont()

    /* Reconstruct w1 */
    w1.caddq()
    w1.useHint(w1, h, params)
    w1.packW1(buffer, params)

    /* Call random oracle and verify challenge */
    val c2 = ByteArrayView(arrays.array, 2 * SEED_BYTES + CRH_BYTES)

    with(params.SHAKE256) {
        absorb(mu, CRH_BYTES)
        absorb(buffer, params.K * params.POLYNOMIAL_W1_PACKED_BYTES)
        doFinal(c2.array, c2.offset, SEED_BYTES)
    }

    return (0 until SEED_BYTES).all { c[it] == c2[it] }
}

/**
 * Parses [signedMessage] (of length [signedMessageLength]).
 * If it contains a valid signature, copies message from it to [message] and returns its length.
 * Otherwise, returns `-1` and doesn't modify [message].
 **/
fun dilithiumOpenSignature(
    message: ByteArray,
    signedMessage: ByteArray,
    signedMessageLength: Int,
    publicKey: ByteArray,
    params: DilithiumParams
): Int {
    if (signedMessageLength >= params.SIGNATURE_BYTES) {
        val len = signedMessageLength - params.SIGNATURE_BYTES
        if (verifySignature(
                ByteArrayView(signedMessage),
                params.SIGNATURE_BYTES,
                ByteArrayView(signedMessage, params.SIGNATURE_BYTES),
                len,
                publicKey,
                params
            )
        ) {
            System.arraycopy(signedMessage, params.SIGNATURE_BYTES, message, 0, len)
            return len
        }
    }

    /* signature verification failed */
    return -1;
}