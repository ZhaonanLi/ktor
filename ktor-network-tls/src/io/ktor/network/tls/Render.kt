package io.ktor.network.tls

import io.ktor.network.tls.extensions.*
import kotlinx.io.core.*
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import kotlin.coroutines.experimental.*


fun makeHandshakeRecord(handshakeType: TLSHandshakeType, block: BytePacketBuilder.() -> Unit): TLSRecord {
    val handshakeBody = buildPacket(block = block)

    val recordBody = buildPacket {
        writeTLSHandshakeType(handshakeType, handshakeBody.remaining)
        writePacket(handshakeBody)
    }

    return TLSRecord().apply {
        type = TLSRecordType.Handshake
        length = recordBody.remaining
        packet = recordBody
    }
}

fun BytePacketBuilder.writeTLSHandshakeType(type: TLSHandshakeType, length: Int) {
    if (length > 0xffffff) throw TLSException("TLS handshake size limit exceeded: $length")
    val v = (type.code shl 24) or length
    writeInt(v)
}

fun BytePacketBuilder.writeTLSClientHello(
    version: TLSVersion,
    suites: List<CipherSuite>,
    random: ByteArray,
    sessionId: ByteArray,
    serverName: String? = null
) {
    writeShort(version.code.toShort())
    writeFully(random)

    val sessionIdLength = sessionId.size
    if (sessionIdLength < 0 || sessionIdLength > 0xff || sessionIdLength > sessionId.size) throw TLSException(
        "Illegal sessionIdLength"
    )

    writeByte(sessionIdLength.toByte())
    writeFully(sessionId, 0, sessionIdLength)

    writeShort((suites.size * 2).toShort())
    for (suite in suites) {
        writeShort(suite.code)
    }

    // compression is always null
    writeByte(1)
    writeByte(0)

    val extensions = ArrayList<ByteReadPacket>()
    extensions += buildSignatureAlgorithmsExtension()
    serverName?.let { name ->
        extensions += buildServerNameExtension(name)
    }

    writeShort(extensions.sumBy { it.remaining }.toShort())
    for (e in extensions) {
        writePacket(e)
    }
}

private fun buildSignatureAlgorithmsExtension(
    algorithms: List<HashAndSign> = SupportedSignatureAlgorithms
): ByteReadPacket = buildPacket {
    writeShort(0x000d) // signature_algorithms extension

    val size = algorithms.size
    writeShort((2 + size * 2).toShort()) // length in bytes
    writeShort((size * 2).toShort()) // length in bytes

    algorithms.forEach {
        writeByte(it.hash.code)
        writeByte(it.sign.code)
    }
}

private fun buildServerNameExtension(name: String): ByteReadPacket {
    return buildPacket {
        writeShort(0) // server_name
        writeShort((name.length + 2 + 1 + 2).toShort()) // lengthh
        writeShort((name.length + 2 + 1).toShort()) // list length
        writeByte(0) // type: host_name
        writeShort(name.length.toShort()) // name length
        writeStringUtf8(name)
    }
}

fun BytePacketBuilder.writeEncryptedPreMasterSecret(
    preSecret: ByteArray,
    publicKey: PublicKey,
    random: SecureRandom
) {
    require(preSecret.size == 48)

    val rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")!!
    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, random)
    val encryptedSecret = rsaCipher.doFinal(preSecret)

    if (encryptedSecret.size > 0xffff) throw TLSException("Encrypted premaster secret is too long")

    writeShort(encryptedSecret.size.toShort())
    writeFully(encryptedSecret)
}
//
//fun BytePacketBuilder.writeChangeCipherSpec(header: TLSRecordHeader) {
//    header.type = TLSRecordType.ChangeCipherSpec
//    header.length = 1
//
//    writeTLSHeader(header)
//    writeByte(1)
//}

internal suspend fun finished(
    messages: List<ByteReadPacket>,
    baseHash: String,
    secretKey: SecretKeySpec,
    coroutineContext: CoroutineContext
): ByteReadPacket {
    val digestBytes = hashMessages(messages, baseHash, coroutineContext)
    return finished(digestBytes, secretKey)
}

internal fun finished(digest: ByteArray, secretKey: SecretKey) = buildPacket {
    val prf = PRF(secretKey, CLIENT_FINISHED_LABEL, digest, 12)
    writeFully(prf)
}

internal fun serverFinished(handshakeHash: ByteArray, secretKey: SecretKey, length: Int = 12): ByteArray =
    PRF(secretKey, SERVER_FINISHED_LABEL, handshakeHash, length)
