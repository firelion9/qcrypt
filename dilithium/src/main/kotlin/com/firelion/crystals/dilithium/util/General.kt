package com.firelion.crystals.dilithium.util

internal inline fun IntArray.mapInPlace(action: (oldValue: Int) -> Int): IntArray = apply {
    indices.forEach {
        this[it] = action(this[it])
    }
}

internal inline fun IntArray.reinitialize(action: (index: Int) -> Int): IntArray = apply {
    indices.forEach {
        this[it] = action(it)
    }
}

internal infix fun Byte.shl(count: Int): Byte = (toIntUnsigned() shl count).toByte()
internal infix fun Byte.ushr(count: Int): Byte = (toIntUnsigned() ushr count).toByte()
internal infix fun Byte.or(other: Byte): Byte = (toInt() or other.toInt()).toByte()

internal fun Byte.toIntUnsigned() = toInt() and 0xff
internal fun Short.toIntUnsigned() = toInt() and 0xffff

internal fun Byte.toLongUnsigned() = toLong() and 0xff

internal infix fun Short.ushr(count: Int) = (toIntUnsigned() ushr count).toShort()

/**
 * Loads 3 bytes into a 32-bit integer in little-endian order.
 */
internal fun load24LittleEndian(x: ByteArray, offset: Int) =
    x[offset].toIntUnsigned() or
            (x[offset + 1].toIntUnsigned() shl 8) or
            (x[offset + 2].toIntUnsigned() shl 16)