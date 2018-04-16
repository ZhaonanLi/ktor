package io.ktor.network.tls.extensions

import io.ktor.network.tls.*
import kotlinx.io.core.*

internal enum class HashAlgorithm(val code: Byte) {
    NONE(0),
    MD5(1),
    SHA1(2),
    SHA224(3),
    SHA256(4),
    SHA384(5),
    SHA512(6);

    companion object {
        fun byCode(code: Byte): HashAlgorithm = values().find { it.code == code }
                ?: throw TLSException("Unknown hash algorithm: $code")
    }
}

internal enum class SignatureAlgorithm(val code: Byte) {
    ANON(0),
    RSA(1),
    DSA(2),
    ECDSA(3);

    companion object {
        fun byCode(code: Byte): SignatureAlgorithm = values().find { it.code == code }
                ?: throw TLSException("Unknown signature algorithm: $code")
    }
}

internal class HashAndSign(val hash: HashAlgorithm, val sign: SignatureAlgorithm) {

    constructor(hash: Byte, sign: Byte) : this(HashAlgorithm.byCode(hash), SignatureAlgorithm.byCode(sign))

    val name: String = "${sign.name}With${hash.name}"
}

internal val SupportedSignatureAlgorithms: List<HashAndSign> = listOf(
    HashAndSign(HashAlgorithm.SHA384, SignatureAlgorithm.ECDSA),
    HashAndSign(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA),

    HashAndSign(HashAlgorithm.SHA512, SignatureAlgorithm.RSA),
    HashAndSign(HashAlgorithm.SHA384, SignatureAlgorithm.RSA),
    HashAndSign(HashAlgorithm.SHA256, SignatureAlgorithm.RSA)
)

internal fun ByteReadPacket.parseSignatureAlgorithms(): List<HashAndSign> {
    val length = readShort().toInt() and 0xffff

    val result = mutableListOf<HashAndSign>()
    while (remaining > 0) {
        val hash = readByte()
        val sign = readByte()

        check(sign != SignatureAlgorithm.ANON.code) { "Anonymous signature not al" }

        result += HashAndSign(hash, sign)
    }

    return result
}
