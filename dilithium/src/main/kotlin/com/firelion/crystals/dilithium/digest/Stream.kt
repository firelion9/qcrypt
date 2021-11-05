package com.firelion.crystals.dilithium.digest

import com.firelion.crystals.dilithium.struct.ByteArrayView
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.CRH_BYTES
import com.firelion.crystals.dilithium.util.DilithiumParams.Companion.SEED_BYTES
import com.firelion.crystals.dilithium.util.ushr
import org.bouncycastle.crypto.digests.SHAKEDigest

internal class Stream(private val is256: Boolean) : SHAKEDigest(if (is256) 256 else 128) {
    fun init(seed: ByteArrayView, nonce: Short) {
        reset()

        absorb(seed, if (is256) CRH_BYTES else SEED_BYTES)
        absorb(nonce.toByte())
        absorb((nonce ushr 8).toByte())
    }

    fun squeezeBlocks(out: ByteArrayView, blocks: Int) {
        doOutput(out.array, out.offset, blocks * if (is256) SHAKE256_RATE else SHAKE128_RATE)
    }

    private fun absorb(data: ByteArrayView, size: Int) {
        super.absorb(data.array, data.offset, size)
    }
}