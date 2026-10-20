/*
 * openScale
 * Copyright (C) 2025 olie.xdev <olie.xdeveloper@googlemail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.health.openscale.core.bluetooth.libs

/**
 * Application-channel codec and reassembler for the Xiaomi Body Composition
 * Scale S400 (FE95 GATT service).
 *
 * This is a pure Kotlin/JVM component: no Android, no Bluetooth, no logging of
 * payload bytes. It only frames and re-assembles the transport envelope that
 * carries the (separately encrypted) application messages, so it never sees a
 * key and never depends on [S400StandardAuth].
 *
 * ## Wire framing
 *
 * Every characteristic value written to or notified from a channel
 * characteristic is a single "frame". The first two bytes are a little-endian
 * 16-bit field `H`:
 *
 *  * `H != 0`  -> **data fragment**: `H` is the 1-based fragment index;
 *                 value = `LE16(seq) || payload`.
 *  * `H == 0`  -> **control frame**: `byte[2]` is the control type and
 *                 `byte[3]` is the application *package type* (an opaque,
 *                 per-message selector; e.g. StandardAuth login uses 10..13).
 *
 * | type | name           | layout                                          |
 * |------|----------------|-------------------------------------------------|
 * | 0    | FRAGMENT_START | `00 00 00 pkg LE16(frameCount)` (exactly 6 bytes)|
 * | 1    | ACK            | `00 00 01 status [LE16(seq)...]`                 |
 * | 2    | SINGLE         | `00 00 02 pkg payload`                           |
 * | 3    | SINGLE_ACK     | `00 00 03 pkg` (4 bytes)                         |
 * | 4    | MANAGEMENT     | `00 00 04 pkg payload`                           |
 * | 5    | MANAGEMENT_ACK | `00 00 05 pkg payload`                           |
 *
 * Vendor mapping (`_m_j.mdj` packet subclasses `k53`/`o000O0O0`/`b2q`/`szp`/
 * `wrf`/`vrf`, dispatched in `_m_j.cc4.o000oOoO`): `ctr`, `ack`, `single_ctr`,
 * `single_ack`, `mng`, `mng_ack`, `data`.
 *
 * ## Fragmentation and the channel opcode
 *
 * When sending, the vendor chooses a flow packet by its *opcode*
 * (`cc4.Ooooo0o`): `0` = always fragment (FRAGMENT_START + data frames),
 * `2` = single frame (SINGLE) when one frame suffices, `4` = management.
 * `frameCount = ceil(totalBytes / payloadCapacity)` (`cc4.Oooo0O0`, CRC32 not
 * used for the S400 because `SpecChannelManager.OooOOo()` returns `false`).
 *
 * ## MTU-sensitive lengths
 *
 * `ChannelManager.BleChannel` stores the negotiated ATT MTU and derives the
 * per-frame payload capacity `DMTU = attMtu - 5` (default 18 at ATT MTU 23).
 * A data frame value is therefore `2 + payload <= attMtu - 3`, the maximum ATT
 * write/notification value. The captured S400 negotiates ATT MTU 247
 * (`Exchange MTU Response = 247`), giving a maximum frame value of 244 bytes
 * and a maximum data payload of 242 bytes.
 *
 * ## Acknowledgement behaviour
 *
 *  * A received FRAGMENT_START is answered with `ACK status = 1` (grant); the
 *    sender then emits the fragments.
 *  * Once all fragments are received the receiver answers `ACK status = 0`
 *    (complete). The sender waits for status 1 before fragmenting and status 0
 *    before considering the message delivered (`cc4.OooO0O0`).
 *  * A received SINGLE is answered with a SINGLE_ACK (`szp`); status 2 requests
 *    a resend, status 0 is success (`cc4.OooO00o`).
 *  * MANAGEMENT frames are answered with MANAGEMENT_ACK and are used for the
 *    initial DMTU/package-count handshake (`cc4.o00O0O`, `cc4.OooO0O0`).
 *
 * ## Reassembly isolation
 *
 * Fragment indices restart at 1 for every message, and the S400 uses several
 * channel characteristics at once (captured ATT value handles `0x001e`,
 * `0x0027`, `0x002a`, each with its own direction). Reassembly state is
 * therefore keyed by **(direction, characteristic)** and never mixes streams,
 * which is exactly what [S400ChannelReassembler] enforces.
 *
 * Evidence: vendor JADX `cc4`/`mdj`/`k53`/`wrf`/`b2q`/`o000O0O0`/`yf6` and the
 * private `weighin_btsnoop_hci.log` capture (framing headers only; no payload
 * is decoded or reproduced here).
 */
enum class S400ChannelDirection {
    /** Frames written by the app (ATT write / write-command). */
    APP_TO_DEVICE,

    /** Frames notified by the device (ATT handle-value-notification). */
    DEVICE_TO_APP,
}

/** Control-frame type stored in `byte[2]` of a zero-header frame. */
enum class S400ControlType(val code: Int) {
    FRAGMENT_START(0),
    ACK(1),
    SINGLE(2),
    SINGLE_ACK(3),
    MANAGEMENT(4),
    MANAGEMENT_ACK(5);

    companion object {
        private val BY_CODE = entries.associateBy { it.code }

        fun fromCode(code: Int): S400ControlType? = BY_CODE[code]
    }
}

/** A decoded channel frame (envelope only; the payload is still opaque). */
sealed class S400ChannelFrame {

    /** `00 00 00 pkg LE16(frameCount)` – start of a fragmented message. */
    data class FragmentStart(val packageType: Int, val frameCount: Int) : S400ChannelFrame()

    /** `00 00 01 status [LE16(seq)...]` – flow control / delivery ack. */
    data class Ack(val status: Int, val sequences: List<Int>) : S400ChannelFrame()

    /** `00 00 02 pkg payload` – an unfragmented application message. */
    class Single(val packageType: Int, val payload: ByteArray) : S400ChannelFrame() {
        override fun equals(other: Any?): Boolean =
            other is Single && other.packageType == packageType && other.payload.contentEquals(payload)

        override fun hashCode(): Int = 31 * packageType + payload.contentHashCode()
    }

    /** `00 00 03 pkg` – ack for a [Single]. */
    data class SingleAck(val packageType: Int) : S400ChannelFrame()

    /** `00 00 04 pkg payload` – management / handshake frame. */
    class Management(val packageType: Int, val payload: ByteArray) : S400ChannelFrame() {
        override fun equals(other: Any?): Boolean =
            other is Management && other.packageType == packageType && other.payload.contentEquals(payload)

        override fun hashCode(): Int = 31 * packageType + payload.contentHashCode()
    }

    /** `00 00 05 pkg payload` – management acknowledgement. */
    class ManagementAck(val packageType: Int, val payload: ByteArray) : S400ChannelFrame() {
        override fun equals(other: Any?): Boolean =
            other is ManagementAck && other.packageType == packageType && other.payload.contentEquals(payload)

        override fun hashCode(): Int = 31 * packageType + payload.contentHashCode()
    }

    /** `LE16(seq) payload` – one fragment of a fragmented message. */
    class Data(val sequence: Int, val payload: ByteArray) : S400ChannelFrame() {
        override fun equals(other: Any?): Boolean =
            other is Data && other.sequence == sequence && other.payload.contentEquals(payload)

        override fun hashCode(): Int = 31 * sequence + payload.contentHashCode()
    }
}

/**
 * Stateless frame codec. All methods are pure and bounded; malformed input is
 * rejected with `null` rather than thrown from [decode].
 */
object S400ChannelCodec {

    /** Little-endian 16-bit header / sequence field. */
    const val HEADER_BYTES = 2

    /** Header + control type + package-type byte. */
    const val CONTROL_HEADER_BYTES = 4

    /** A FRAGMENT_START frame is exactly 6 bytes on the wire. */
    const val FRAGMENT_START_FRAME_LENGTH = 6

    /** A control frame with no extra body (ACK, SINGLE_ACK). */
    const val CONTROL_FRAME_LENGTH = 4

    /** Upper bound on `frameCount`, matching the observed protocol and helper. */
    const val MAX_FRAME_COUNT = 32

    /** Highest fragment index representable in the 16-bit header. */
    const val MAX_FRAGMENT_SEQUENCE = 0xFFFF

    /** Default BLE ATT MTU before negotiation. */
    const val DEFAULT_ATT_MTU = 23

    /** ATT MTU the captured S400 negotiated (Exchange MTU Response). */
    const val S400_ATT_MTU = 247

    /** `status` granted by the receiver after a FRAGMENT_START. */
    const val ACK_STATUS_CONTINUE = 1

    /** `status` reported by the receiver once a fragmented message is complete. */
    const val ACK_STATUS_COMPLETE = 0

    /** `status` used by a SINGLE_ACK to request a resend. */
    const val ACK_STATUS_RESEND = 2

    /** The package type the app uses for its own acks (captured as 0). */
    const val ACK_PACKAGE_TYPE = 0

    /** Vendor "opcode" selector for a fragmented (FRAGMENT_START) message. */
    const val OPCODE_FRAGMENT = 0

    /** Vendor "opcode" selector for a single-frame message. */
    const val OPCODE_SINGLE = 2

    /** Vendor "opcode" selector for a management frame. */
    const val OPCODE_MANAGEMENT = 4

    /** Default per-frame payload capacity at [DEFAULT_ATT_MTU] (23 - 5). */
    const val DEFAULT_PAYLOAD_CAPACITY = 18

    /** Per-frame payload capacity at the S400's negotiated MTU (247 - 5). */
    const val S400_PAYLOAD_CAPACITY = 242

    /** Maximum data-frame payload accepted when decoding (247 - 5). */
    const val MAX_FRAGMENT_PAYLOAD = S400_PAYLOAD_CAPACITY

    /** Maximum characteristic value accepted when decoding (247 - 3). */
    const val MAX_FRAME_VALUE_LENGTH = S400_ATT_MTU - 3

    /** Per-frame payload capacity for a negotiated ATT MTU (`DMTU = mtu - 5`). */
    fun payloadCapacityForMtu(attMtu: Int): Int = (attMtu - 5).coerceAtLeast(0)

    /** Maximum characteristic value length for a negotiated ATT MTU (`mtu - 3`). */
    fun maxFrameValueLengthForMtu(attMtu: Int): Int = (attMtu - 3).coerceAtLeast(0)

    /**
     * Decode one characteristic value into a frame.
     *
     * @param maxFrameLength reject values longer than this (default: the
     *   largest legal value at the S400's negotiated MTU).
     * @return the decoded frame, or `null` if the value is malformed, over
     *   sized, or carries an unknown control type.
     */
    fun decode(value: ByteArray, maxFrameLength: Int = MAX_FRAME_VALUE_LENGTH): S400ChannelFrame? {
        if (value.size < HEADER_BYTES || value.size > maxFrameLength) return null

        val header = readU16(value, 0)
        if (header != 0) {
            return S400ChannelFrame.Data(header, value.copyOfRange(HEADER_BYTES, value.size))
        }
        if (value.size < CONTROL_HEADER_BYTES) return null

        val type = S400ControlType.fromCode(value[2].toInt() and 0xFF) ?: return null
        val packageType = value[3].toInt() and 0xFF
        return when (type) {
            S400ControlType.FRAGMENT_START -> {
                if (value.size != FRAGMENT_START_FRAME_LENGTH) return null
                S400ChannelFrame.FragmentStart(packageType, readU16(value, 4))
            }
            S400ControlType.ACK -> {
                val body = value.size - CONTROL_HEADER_BYTES
                if (body % 2 != 0) return null
                val sequences = ArrayList<Int>(body / 2)
                var i = CONTROL_HEADER_BYTES
                while (i < value.size) {
                    sequences.add(readU16(value, i))
                    i += 2
                }
                S400ChannelFrame.Ack(packageType, sequences)
            }
            S400ControlType.SINGLE ->
                S400ChannelFrame.Single(packageType, value.copyOfRange(CONTROL_HEADER_BYTES, value.size))
            S400ControlType.SINGLE_ACK -> S400ChannelFrame.SingleAck(packageType)
            S400ControlType.MANAGEMENT ->
                S400ChannelFrame.Management(packageType, value.copyOfRange(CONTROL_HEADER_BYTES, value.size))
            S400ControlType.MANAGEMENT_ACK ->
                S400ChannelFrame.ManagementAck(packageType, value.copyOfRange(CONTROL_HEADER_BYTES, value.size))
        }
    }

    /** Encode a FRAGMENT_START (`opcode = 0`). */
    fun fragmentStart(packageType: Int, frameCount: Int): ByteArray {
        require(frameCount in 1..MAX_FRAME_COUNT) { "frameCount out of range: $frameCount" }
        val out = ByteArray(FRAGMENT_START_FRAME_LENGTH)
        writeU16(out, 0, 0)
        out[2] = S400ControlType.FRAGMENT_START.code.toByte()
        out[3] = packageByte(packageType)
        writeU16(out, 4, frameCount)
        return out
    }

    /** Encode an ACK; [sequences] is the (usually empty) resend request list. */
    fun ack(status: Int, sequences: List<Int> = emptyList()): ByteArray {
        val out = ByteArray(CONTROL_HEADER_BYTES + sequences.size * 2)
        writeU16(out, 0, 0)
        out[2] = S400ControlType.ACK.code.toByte()
        out[3] = statusByte(status)
        var i = CONTROL_HEADER_BYTES
        for (sequence in sequences) {
            require(sequence in 0..MAX_FRAGMENT_SEQUENCE) { "sequence out of range: $sequence" }
            writeU16(out, i, sequence)
            i += 2
        }
        return out
    }

    /** Encode a SINGLE frame (`opcode = 2`). */
    fun single(packageType: Int, payload: ByteArray): ByteArray {
        val out = ByteArray(CONTROL_HEADER_BYTES + payload.size)
        writeU16(out, 0, 0)
        out[2] = S400ControlType.SINGLE.code.toByte()
        out[3] = packageByte(packageType)
        System.arraycopy(payload, 0, out, CONTROL_HEADER_BYTES, payload.size)
        return out
    }

    /** Encode a SINGLE_ACK reply for a SINGLE frame. */
    fun singleAck(packageType: Int = ACK_PACKAGE_TYPE): ByteArray {
        val out = ByteArray(CONTROL_FRAME_LENGTH)
        writeU16(out, 0, 0)
        out[2] = S400ControlType.SINGLE_ACK.code.toByte()
        out[3] = packageByte(packageType)
        return out
    }

    /** Encode a MANAGEMENT frame (`opcode = 4`). */
    fun management(packageType: Int, payload: ByteArray): ByteArray =
        controlWithPayload(S400ControlType.MANAGEMENT, packageType, payload)

    /** Encode a MANAGEMENT_ACK frame. */
    fun managementAck(packageType: Int, payload: ByteArray): ByteArray =
        controlWithPayload(S400ControlType.MANAGEMENT_ACK, packageType, payload)

    /** Encode one data fragment (`LE16(seq) payload`). */
    fun dataFragment(sequence: Int, payload: ByteArray): ByteArray {
        require(sequence in 1..MAX_FRAGMENT_SEQUENCE) { "sequence out of range: $sequence" }
        val out = ByteArray(HEADER_BYTES + payload.size)
        writeU16(out, 0, sequence)
        System.arraycopy(payload, 0, out, HEADER_BYTES, payload.size)
        return out
    }

    /**
     * Split one application message into the outgoing frame list.
     *
     * Returns a single SINGLE frame when the message fits in one frame, or a
     * FRAGMENT_START followed by `frameCount` data frames otherwise. Pass
     * [forceFragmented] to always use the fragmented form (vendor
     * `opcode = 0`), even for a one-frame message.
     *
     * @param capacity per-frame payload capacity (`DMTU`, default 18).
     * @throws IllegalArgumentException if the message needs more than
     *   [MAX_FRAME_COUNT] frames.
     */
    fun fragment(
        packageType: Int,
        payload: ByteArray,
        capacity: Int = DEFAULT_PAYLOAD_CAPACITY,
        forceFragmented: Boolean = false,
    ): List<ByteArray> {
        require(capacity >= 1) { "capacity must be positive" }
        val frameCount = if (payload.isEmpty()) 1 else (payload.size + capacity - 1) / capacity
        require(frameCount <= MAX_FRAME_COUNT) {
            "message needs $frameCount frames, limit is $MAX_FRAME_COUNT"
        }

        if (!forceFragmented && frameCount == 1) {
            return listOf(single(packageType, payload))
        }

        val frames = ArrayList<ByteArray>(frameCount + 1)
        frames.add(fragmentStart(packageType, frameCount))
        var offset = 0
        for (sequence in 1..frameCount) {
            val end = minOf(offset + capacity, payload.size)
            frames.add(dataFragment(sequence, payload.copyOfRange(offset, end)))
            offset = end
        }
        return frames
    }

    private fun controlWithPayload(type: S400ControlType, packageType: Int, payload: ByteArray): ByteArray {
        val out = ByteArray(CONTROL_HEADER_BYTES + payload.size)
        writeU16(out, 0, 0)
        out[2] = type.code.toByte()
        out[3] = packageByte(packageType)
        System.arraycopy(payload, 0, out, CONTROL_HEADER_BYTES, payload.size)
        return out
    }
}

/** Outcome of feeding one frame to the [S400ChannelReassembler]. */
sealed class S400ChannelEvent {

    /**
     * A complete application message. For [fragmented] messages the receiver
     * must answer with `ACK status = 0`; for a single-frame message it must
     * answer with a SINGLE_ACK.
     */
    class Message(val packageType: Int, val payload: ByteArray, val fragmented: Boolean) : S400ChannelEvent() {
        override fun equals(other: Any?): Boolean =
            other is Message && other.packageType == packageType &&
                other.fragmented == fragmented && other.payload.contentEquals(payload)

        override fun hashCode(): Int = 31 * (31 * packageType + payload.contentHashCode()) + if (fragmented) 1 else 0
    }

    /** A received flow-control ack. */
    data class Ack(val status: Int, val sequences: List<Int>) : S400ChannelEvent()

    /** The receiver must send an ack with this [status] (and resend [sequences]). */
    data class AckRequired(val status: Int, val sequences: List<Int>) : S400ChannelEvent()

    /** A received management frame ([acknowledgement] distinguishes type 4/5). */
    class Management(val packageType: Int, val payload: ByteArray, val acknowledgement: Boolean) :
        S400ChannelEvent() {
        override fun equals(other: Any?): Boolean =
            other is Management && other.packageType == packageType &&
                other.acknowledgement == acknowledgement && other.payload.contentEquals(payload)

        override fun hashCode(): Int =
            31 * (31 * packageType + payload.contentHashCode()) + if (acknowledgement) 1 else 0
    }

    /** A frame that could not be accepted; [reason] explains why. */
    data class Rejected(val reason: String) : S400ChannelEvent()

    /** A frame that was consumed without producing an event (e.g. progress). */
    data object Ignored : S400ChannelEvent()
}

/**
 * Per-connection frame reassembler.
 *
 * State is isolated per `(direction, characteristic)` stream so fragments from
 * different directions or characteristics can never be concatenated. Every
 * buffered message is bounded by [maxFrameCount] fragments and by
 * [maxFragmentPayload] bytes per fragment, so a hostile peer cannot grow the
 * buffer without limit.
 */
class S400ChannelReassembler(
    /** Maximum bytes accepted in one data fragment. */
    private val maxFragmentPayload: Int = S400ChannelCodec.MAX_FRAGMENT_PAYLOAD,
    /** Maximum fragment count accepted in a FRAGMENT_START. */
    private val maxFrameCount: Int = S400ChannelCodec.MAX_FRAME_COUNT,
) {

    private class Stream(val packageType: Int, val expected: Int) {
        val parts = HashMap<Int, ByteArray>(expected)
    }

    private data class Key(val direction: S400ChannelDirection, val characteristic: Int)

    private val streams = HashMap<Key, Stream>()

    /** Number of streams currently holding a partially received message. */
    val pendingStreamCount: Int get() = streams.size

    /**
     * Feed one frame for [direction]/[characteristic].
     *
     * @return zero or more events; a FRAGMENT_START yields
     *   `AckRequired(status = 1)`, a completed message yields a [S400ChannelEvent.Message]
     *   (and, for a fragmented message, `AckRequired(status = 0)`).
     */
    fun accept(
        direction: S400ChannelDirection,
        characteristic: Int,
        frame: S400ChannelFrame,
    ): List<S400ChannelEvent> {
        val key = Key(direction, characteristic)
        return when (frame) {
            is S400ChannelFrame.FragmentStart -> startFragmented(key, frame)
            is S400ChannelFrame.Data -> accumulate(key, frame)
            is S400ChannelFrame.Single -> listOf(S400ChannelEvent.Message(frame.packageType, frame.payload, false))
            is S400ChannelFrame.Ack -> listOf(S400ChannelEvent.Ack(frame.status, frame.sequences))
            is S400ChannelFrame.SingleAck -> emptyList()
            is S400ChannelFrame.Management ->
                listOf(S400ChannelEvent.Management(frame.packageType, frame.payload, false))
            is S400ChannelFrame.ManagementAck ->
                listOf(S400ChannelEvent.Management(frame.packageType, frame.payload, true))
        }
    }

    private fun startFragmented(key: Key, frame: S400ChannelFrame.FragmentStart): List<S400ChannelEvent> {
        streams.remove(key)
        if (frame.frameCount !in 1..maxFrameCount) {
            return listOf(S400ChannelEvent.Rejected("frameCount out of range: ${frame.frameCount}"))
        }
        streams[key] = Stream(frame.packageType, frame.frameCount)
        return listOf(S400ChannelEvent.AckRequired(S400ChannelCodec.ACK_STATUS_CONTINUE, emptyList()))
    }

    private fun accumulate(key: Key, frame: S400ChannelFrame.Data): List<S400ChannelEvent> {
        val stream = streams[key]
            ?: return listOf(S400ChannelEvent.Rejected("data fragment without a fragment-start"))
        if (frame.payload.size > maxFragmentPayload) {
            streams.remove(key)
            return listOf(S400ChannelEvent.Rejected("fragment payload exceeds $maxFragmentPayload bytes"))
        }
        if (frame.sequence !in 1..stream.expected) {
            streams.remove(key)
            return listOf(S400ChannelEvent.Rejected("fragment sequence out of range: ${frame.sequence}"))
        }
        if (stream.parts.put(frame.sequence, frame.payload) != null) {
            streams.remove(key)
            return listOf(S400ChannelEvent.Rejected("duplicate fragment sequence: ${frame.sequence}"))
        }
        if (stream.parts.size < stream.expected) {
            return emptyList()
        }

        streams.remove(key)
        var total = 0
        for (sequence in 1..stream.expected) total += stream.parts.getValue(sequence).size
        val assembled = ByteArray(total)
        var offset = 0
        for (sequence in 1..stream.expected) {
            val part = stream.parts.getValue(sequence)
            System.arraycopy(part, 0, assembled, offset, part.size)
            offset += part.size
        }
        return listOf(
            S400ChannelEvent.Message(stream.packageType, assembled, true),
            S400ChannelEvent.AckRequired(S400ChannelCodec.ACK_STATUS_COMPLETE, emptyList()),
        )
    }

    /** Drop the partially received message for one stream, if any. */
    fun reset(direction: S400ChannelDirection, characteristic: Int) {
        streams.remove(Key(direction, characteristic))
    }

    /** Drop all partially received messages. */
    fun reset() {
        streams.clear()
    }
}

private fun readU16(bytes: ByteArray, offset: Int): Int =
    (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

private fun writeU16(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = (value and 0xFF).toByte()
    bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
}

private fun packageByte(packageType: Int): Byte {
    require(packageType in 0..0xFF) { "packageType out of range: $packageType" }
    return packageType.toByte()
}

private fun statusByte(status: Int): Byte {
    require(status in 0..0xFF) { "status out of range: $status" }
    return status.toByte()
}
