package com.firelion.crystals.kyber

import java.io.InputStream
import kotlin.experimental.and

fun ByteArray.toHexString(): String =
    joinToString(":") { (it.toInt() ushr 4 and 0xf).toString(16) + (it and 0xf).toString(16) }


fun InputStream.readToBuffer(buf: ByteArray) {
    var l = 0

    while (l < buf.size) {
        l += read(buf, l, buf.size - l)
    }
}