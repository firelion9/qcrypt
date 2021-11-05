package com.firelion.crystals.dilithium.struct

internal class ByteArrayView(internal val array: ByteArray, internal var offset: Int = 0) {
    constructor(size: Int) : this(ByteArray(size), 0)

    operator fun plusAssign(offset: Int) {
        this.offset += offset
    }

    operator fun minusAssign(offset: Int) {
        this.offset -= offset
    }

    operator fun get(index: Int) = array[offset + index]
    operator fun set(index: Int, value: Byte) {
        array[offset + index] = value
    }
}

internal fun ByteArrayView.copyTo(other: ByteArrayView, length: Int) =
    System.arraycopy(array, offset, other.array, other.offset, length)

internal class IntArrayView(internal val array: IntArray, internal var offset: Int = 0) {
    operator fun plusAssign(offset: Int) {
        this.offset += offset
    }

    operator fun minusAssign(offset: Int) {
        this.offset -= offset
    }

    operator fun get(index: Int) = array[offset + index]
    operator fun set(index: Int, value: Int) {
        array[offset + index] = value
    }
}