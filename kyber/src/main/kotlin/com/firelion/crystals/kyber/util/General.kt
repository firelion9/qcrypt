package com.firelion.crystals.kyber.util

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

internal fun Byte.toIntUnsigned() = toInt() and 0xff
