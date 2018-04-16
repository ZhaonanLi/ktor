package io.ktor.network.tls

import kotlinx.coroutines.experimental.io.packet.ByteReadPacket

class TLSRecord {
    var type: TLSRecordType = TLSRecordType.Handshake
    var version: TLSVersion = TLSVersion.TLS12
    var length: Int = 0
    var packet = ByteReadPacket.Empty
}

class TLSHandshake {
    var type: TLSHandshakeType = TLSHandshakeType.HelloRequest
    var length: Int = 0
    var packet = ByteReadPacket.Empty
}