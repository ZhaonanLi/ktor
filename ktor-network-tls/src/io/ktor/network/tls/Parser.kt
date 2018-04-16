package io.ktor.network.tls

import io.ktor.network.tls.extensions.*
import kotlinx.coroutines.experimental.channels.*
import kotlinx.coroutines.experimental.io.*
import kotlinx.io.core.*
import java.io.*
import java.security.cert.*
import kotlin.experimental.*

private const val MAX_TLS_FRAME_SIZE = 0x4800

internal suspend fun ByteReadChannel.readTLSRecord(header: TLSRecord): Boolean {
    println("read code")
    val typeCode = try {
        readByte().toInt() and 0xff
    } catch (t: ClosedReceiveChannelException) {
        return false
    }
    header.type = TLSRecordType.byCode(typeCode)
    println("read version")
    header.version = readTLSVersion()
    println("read length")
    header.length = readShort().toInt() and 0xffff

    if (header.length > MAX_TLS_FRAME_SIZE) throw TLSException("Illegal TLS frame size: ${header.length}")

    println("read packet")
    header.packet = readPacket(header.length)
    return true
}

internal suspend fun ByteReadChannel.readTLSHandshake(header: TLSRecord, handshake: TLSHandshake) {
    if (header.type !== TLSRecordType.Handshake) throw TLSException("Expected TLS handshake but got ${header.type}")

    val v = readInt()
    handshake.type = TLSHandshakeType.byCode(v ushr 24)
    handshake.length = v and 0xffffff
}

internal fun ByteReadPacket.readTLSHandshake(): TLSHandshake = TLSHandshake().apply {
    val typeAndVersion = readInt()
    type = TLSHandshakeType.byCode(typeAndVersion ushr 24)
    length = typeAndVersion and 0xffffff
    packet = buildPacket {
        writeFully(readBytes(length))
    }
}

internal fun ByteReadPacket.readTLSServerHello(): TLSServerHello {
    val version = readTLSVersion()

    val random = ByteArray(32)
    readFully(random)
    val sessionIdLength = readByte().toInt() and 0xff

    if (sessionIdLength > 32) throw TLSException("sessionId length limit of 32 bytes exceeded: $sessionIdLength specified")

    val sessionId = ByteArray(32)
    readFully(sessionId, 0, sessionIdLength)

    val suite = readShort()

    val compressionMethod = readByte().toShort() and 0xff
    if (compressionMethod.toInt() != 0) throw TLSException("Unsupported TLS compression method $compressionMethod (only null 0 compression method is supported)")

    if (remaining == 0) return TLSServerHello(version, random, sessionId, suite, compressionMethod)

    // handle extensions
    val extensionSize = readShort().toInt() and 0xffff

    if (remaining != extensionSize)
        throw TLSException("Invalid extensions size: requested $extensionSize, available $remaining")

    val extensions = mutableListOf<TLSExtension>()
    while (remaining > 0) {
        val type = readShort().toInt() and 0xffff
        val length = readShort().toInt() and 0xffff

        extensions += TLSExtension(
            TLSExtensionType.byCode(type), length,
            buildPacket { writeFully(readBytes(length)) }
        )
    }

    return TLSServerHello(version, random, sessionId, suite, compressionMethod, extensions)
}


internal fun ByteReadPacket.readTLSServerKeyExchange(): Int {
    val type = readByte().toInt() and 0xff
    when (ServerKeyExchangeType.byCode(type)) {
        ServerKeyExchangeType.NamedCurve -> {
            val curveId = readShort().toInt() and 0xffff

            check(SupportedNamedCurves.isValid(curveId))
            return curveId
        }
        ServerKeyExchangeType.ExplicitPrime -> TODO()
        ServerKeyExchangeType.ExplicitChar -> TODO()
    }
}

internal fun ByteReadPacket.readTLSCertificate(): List<Certificate> {
    val certificatesChainLength = readTripleByteLength()
    var certificateBase = 0
    val result = ArrayList<Certificate>()
    val factory = CertificateFactory.getInstance("X.509")!!

    while (certificateBase < certificatesChainLength) {
        val certificateLength = readTripleByteLength()
        if (certificateLength > (certificatesChainLength - certificateBase)) throw TLSException("Certificate length is too big")
        if (certificateLength > remaining) throw TLSException("Certificate length is too big")

        val certificate = ByteArray(certificateLength)
        readFully(certificate)
        certificateBase += certificateLength + 3

        val x509 = factory.generateCertificate(certificate.inputStream())
        result.add(x509)
    }

    return result
}

internal class TLSException(message: String, cause: Throwable? = null) : IOException(message, cause)

private suspend fun ByteReadChannel.readTLSVersion() =
    TLSVersion.byCode(readShort().toInt() and 0xffff)

private fun ByteReadPacket.readTLSVersion() =
    TLSVersion.byCode(readShort().toInt() and 0xffff)

private fun ByteReadPacket.readTripleByteLength(): Int = (readByte().toInt() and 0xff shl 16) or
        (readShort().toInt() and 0xffff)
