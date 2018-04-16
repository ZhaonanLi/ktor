package io.ktor.network.tls.extensions

import io.ktor.network.tls.*
import kotlinx.io.core.*

internal enum class TLSExtensionType(val code: Short) {
    SIGNATURE_ALGORITHMS(13);

    companion object {
        fun byCode(code: Int): TLSExtensionType =
            values().find { it.code == code.toShort() } ?: throw TLSException("Unknown server hello extension type: $code")
    }
}

internal class TLSExtension(
    val type: TLSExtensionType,
    val length: Int,
    val packet: ByteReadPacket
)
