package com.firelion.crystals.dilithium.util

import com.firelion.crystals.dilithium.struct.ByteArrayView

/**
 * Fills a segment of [out] starting at [offset] with length [length] with random bytes.
 */
internal fun randomBytes(out: ByteArrayView, length: Int, params: DilithiumParams) {
    (0 until length).forEach {
        out[it] = params.random.nextInt(256).toByte()
    }
}