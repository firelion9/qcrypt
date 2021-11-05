package com.firelion.crystals.dilithium.digest

import com.firelion.crystals.dilithium.struct.ByteArrayView
import org.bouncycastle.crypto.digests.SHAKEDigest

internal const val SHAKE128_RATE = 168
internal const val SHAKE256_RATE = 136

internal class Shake(private val is256: Boolean) : SHAKEDigest(if (is256) 256 else 128) {
    fun squeezeBlocks(out: ByteArrayView, blocks: Int) {
        doOutput(out.array, out.offset, blocks * if (is256) SHAKE256_RATE else SHAKE128_RATE)
    }

    fun absorb(data: ByteArrayView, size: Int) {
        super.absorb(data.array, data.offset, size)
    }
}