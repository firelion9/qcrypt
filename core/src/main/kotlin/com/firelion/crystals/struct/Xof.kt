package com.firelion.crystals.struct

import com.firelion.crystals.util.KyberParams.Companion.KYBER_SYMMETRIC_BYTES
import org.bouncycastle.crypto.digests.SHAKEDigest

internal const val XOF_BLOCK_BYTES = 168

internal class Xof : SHAKEDigest(128) {
    fun kyberAbsorb(seed: ByteArray, i: Byte, j: Byte) {
        if (squeezing) reset()

        update(seed, 0, KYBER_SYMMETRIC_BYTES)
        update(i)
        update(j)
    }

    fun squeezeBlocks(buffer: ByteArray, offset: Int, blocks: Int) {
        doOutput(buffer, offset, blocks * XOF_BLOCK_BYTES)
    }
}