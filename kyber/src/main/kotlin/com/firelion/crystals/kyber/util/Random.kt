package com.firelion.crystals.kyber.util

/**
 * Fills a segment of [out] starting at [offset] with length [length] with random bytes.
 */
internal fun randomBytes(out: ByteArray, offset: Int, length: Int, params: KyberParams) {
    (offset until offset + length).forEach {
        out[it] = params.random.nextInt(256).toByte()
    }
}