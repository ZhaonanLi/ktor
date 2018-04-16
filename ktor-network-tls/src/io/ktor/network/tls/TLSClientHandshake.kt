package io.ktor.network.tls

import kotlinx.coroutines.experimental.channels.*
import kotlinx.io.core.ByteReadPacket
import java.security.*
import java.security.cert.*
import javax.net.ssl.*

internal suspend fun tlsClientHandshake(
    input: ReceiveChannel<TLSRecord>,
    output: SendChannel<TLSRecord>,
    trustManager: X509TrustManager? = null,
    serverName: String? = null,
    randomAlgorithm: String = "NativePRNGNonBlocking"
) {
    TLSClientHandshake(input, output, trustManager, serverName, randomAlgorithm).negotiate()
}

private class TLSClientHandshake(
    val input: ReceiveChannel<TLSRecord>,
    val output: SendChannel<TLSRecord>,
    val trustManager: X509TrustManager? = null,
    val serverName: String? = null,
    randomAlgorithm: String = "NativePRNGNonBlocking"
) {
    private val digest = Digest()
    private val clientSeed: ByteArray = generateSeed(randomAlgorithm)

    private lateinit var serverHello: TLSServerHello

    private var curveId: Int? = null
    private var serverKey: PublicKey? = null

    private val filteredInput = produce<TLSRecord> {
        input.consumeEach { record ->
            println("receive record ${record.type}")
            when (record.type) {
                TLSRecordType.Alert -> {
                    val packet = record.packet
                    val level = TLSAlertLevel.byCode(packet.readByte().toInt())
                    val code = TLSAlertType.byCode(packet.readByte().toInt())

                    val cause = TLSException("Received alert during handshake. Level: $level, code: $code")
                    channel.close(cause)
                    return@produce
                }
                TLSRecordType.ChangeCipherSpec -> {
                }
                TLSRecordType.Handshake -> channel.send(record)
                else -> error("Unsupported record type: ${record.type} during handshake")
            }
        }
    }

    private val handshakes = produce<TLSHandshake> {
        println("start handshakes")
        filteredInput.consumeEach { record ->
            println("filter record: ${record.type}")
            val packet = record.packet
            while (packet.remaining > 0) {
                val element = packet.readTLSHandshake()

                // ignore hello requests during negotiation
                if (element.type == TLSHandshakeType.HelloRequest) continue

                digest += element.packet
                channel.send(element)
            }
        }
    }


    suspend fun negotiate() {
        println("start negotiate")
        sendClientHello()
        println("start receive server hello")
        serverHello = receiveServerHello()

        println("start handle certificates")
        handleCertificatesAndKeys()
        receiveHandshakeFinished()
    }

    private suspend fun sendClientHello() {
        val record = makeHandshakeRecord(TLSHandshakeType.ClientHello) {
            // TODO: support session id
            writeTLSClientHello(
                TLSVersion.TLS12, SupportedSuites,
                clientSeed, ByteArray(32), serverName
            )
        }

        digest += record.packet
        output.send(record)
    }

    private suspend fun receiveServerHello(): TLSServerHello {
        val handshake = handshakes.receive()

        check(handshake.type == TLSHandshakeType.ServerHello) {
            ("Expected TLS handshake ServerHello but got ${handshake.type}")
        }

        return handshake.packet.readTLSServerHello()
    }

    private suspend fun handleCertificatesAndKeys() {
        handshakes.consumeEach { handshake ->
            val packet = handshake.packet
            println("handling certificate handshake: ${handshake.type}")
            when (handshake.type) {
                TLSHandshakeType.Certificate -> {
                    val certs = packet.readTLSCertificate()
                    val x509s = certs.filterIsInstance<X509Certificate>()

                    val manager: X509TrustManager = trustManager ?: findTrustManager()
                    manager.checkServerTrusted(x509s.toTypedArray(), "EC")
                }
                TLSHandshakeType.CertificateRequest -> {
                }
                TLSHandshakeType.ServerKeyExchange -> {
                    if (serverHello.cipherSuite.exchangeType != SecretExchangeType.ECDHE_ECDSA)
                        throw TLSException("Server key exchange support only ECDHE_ECDSA exchange for now")

                    curveId = packet.readTLSServerKeyExchange()
                }
                TLSHandshakeType.ServerDone -> {
                    // 2
                }
            }
        }
    }

    private suspend fun handshake(packet: ByteReadPacket) {
//        when (handshakeHeader.type) {
//            TLSHandshakeType.ServerDone -> {
//                preSecret = random.generateSeed(48)
//                preSecret[0] = 0x03
//                preSecret[1] = 0x03 // TLS 1.2
//
//                val secretHandshake = clientKeyExchange(random, handshakeHeader, serverKey!!, preSecret)
//                handshakesPacket.writePacket(secretHandshake.copy())
//
//                recordHeader.type = TLSRecordType.Handshake
//                recordHeader.length = secretHandshake.remaining
//                output.writePacket {
//                    writeTLSHeader(recordHeader)
//                }
//                output.writePacket(secretHandshake)
//
//                output.writePacket {
//                    writeChangeCipherSpec(recordHeader)
//                }
//
//                val hash = doHash()
//                val suite = cipherSuite!!
//                masterSecret = masterSecret(SecretKeySpec(preSecret, suite.macName), TODO(), serverRandom)
//                preSecret.fill(0)
//                preSecret = EmptyByteArray
//
//                val finishedBody = finished(hash, masterSecret!!)
//                val finished = buildPacket {
//                    handshakeHeader.type = TLSHandshakeType.Finished
//                    handshakeHeader.length = finishedBody.remaining
//                    writeTLSHandshake(handshakeHeader)
//                    writePacket(finishedBody)
//                }
//
//                handshakesPacket.writePacket(finished.copy())
//                keyMaterial = keyMaterial(
//                    masterSecret!!,
//                    serverRandom + TODO(),
//                    suite.keyStrengthInBytes,
//                    suite.macStrengthInBytes,
//                    suite.fixedIvLength
//                )
//
//                val cipher = encryptCipher(suite, keyMaterial, TLSRecordType.Handshake, finished.remaining, 0, 0)
//                val finishedEncrypted = finished.encrypted(cipher, 0)
//
//                output.writePacket {
//                    recordHeader.type = TLSRecordType.Handshake
//                    recordHeader.length = finishedEncrypted.remaining
//                    writeTLSHeader(recordHeader)
//                }
//                output.writePacket(finishedEncrypted)
//
//                output.flush()
//            }
//            else -> throw TLSException("Unsupported TLS handshake type ${handshakeHeader.type}")
//        }
    }

    private suspend fun receiveHandshakeFinished() {
//        val encryptedPacket = readRecord()
//        val recordIv = encryptedPacket.readLong()
//        val cipher =
//            decryptCipher(cipherSuite!!, keyMaterial, TLSRecordType.Handshake, recordHeader.length, recordIv, 0)
//        val decrypted = encryptedPacket.decrypted(cipher)
//
//        val body = decrypted.readTLSHandshake(handshakeHeader).readBytes()
//
//        if (handshakeHeader.type != TLSHandshakeType.Finished)
//            throw TLSException("TLS handshake failed: expected Finihsed record after ChangeCipherSpec but got ${handshakeHeader.type}")
//
//        check(decrypted.isEmpty)
//
//        val expectedFinished = serverFinished(doHash(), masterSecret!!, body.size)
//        check(expectedFinished.contentEquals(body)) {
//            """Handshake: ServerFinished verification failed:
//                |Expected: ${expectedFinished.joinToString()}
//                |Actual: ${body.joinToString()}
//            """.trimMargin()
//        }
    }

    private suspend fun changeCipherSpec(flag: Byte) {
//        if (!readTLSRecordHeader()) throw TLSException("Handshake failed: premature end of stream")
//        if (recordHeader.type == TLSRecordType.Handshake) {
//            check(flag == 1.toByte()) { "Flag expected to equals 1 in handshake" }
//            return
//        }
//
//        // TODO: verify flag after handshake
//        throw TLSException("Unexpected record of type ${recordHeader.type} (${recordHeader.length} bytes)")
    }

//    private fun clientKeyExchange(
//        random: SecureRandom,
//        handshake: TLSHandshake,
//        publicKey: PublicKey,
//        preSecret: ByteArray
//    ): ByteReadPacket {
//        require(preSecret.size == 48)
//
//        val secretPacket = WritePacket()
//        val suite = SupportedSuites[handshake.suites[0]]!!
//        secretPacket.writeEncryptedPreMasterSecret(preSecret, publicKey, random)
//
//        handshake.type = TLSHandshakeType.ClientKeyExchange
//        handshake.length = secretPacket.size
//
//        return buildPacket {
//            writeTLSHandshake(handshake)
//            writePacket(secretPacket.build())
//        }
//    }


    private fun findTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers

        return tm.first { it is X509TrustManager } as X509TrustManager
    }
}

private fun generateSeed(algorithm: String): ByteArray =
    SecureRandom.getInstance(algorithm).generateSeed(32).also {
        val unixTime = (System.currentTimeMillis() / 1000L)
        it[0] = (unixTime shr 24).toByte()
        it[1] = (unixTime shr 16).toByte()
        it[2] = (unixTime shr 8).toByte()
        it[3] = (unixTime shr 0).toByte()
    }

