package io.ktor.network.tls

import kotlinx.coroutines.experimental.channels.*
import kotlinx.coroutines.experimental.io.*
import kotlin.coroutines.experimental.*

fun ByteReadChannel.tlsRecordChannel(
    coroutineContext: CoroutineContext
): ReceiveChannel<TLSRecord> = produce(coroutineContext) {
    val record = TLSRecord()
    println("start receiving")
    while (readTLSRecord(record)) {
        println("received record: ${record.type}")
        channel.send(record)
    }
}

fun ByteWriteChannel.tlsRecordChannel(
    coroutineContext: CoroutineContext
): SendChannel<TLSRecord> = actor(coroutineContext) {
    channel.consumeEach {
        println("sending record: ${it.type}")

        writeByte(it.type.code.toByte())
        writeShort(it.version.code.toShort())
        writeShort(it.length.toShort())

        writePacket(it.packet)
        flush()
        println("sending record: ${it.type} [DONE]")
    }
}
