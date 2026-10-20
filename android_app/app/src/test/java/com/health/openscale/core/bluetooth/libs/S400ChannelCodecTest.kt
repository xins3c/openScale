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

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Unit tests for [S400ChannelCodec] and [S400ChannelReassembler].
 *
 * These are standalone tests of the transport envelope only. Every fixture is
 * a synthetic, hand-written byte string (no device token, no session key, no
 * captured plaintext, no health data). The header layouts they pin were
 * reconstructed from the vendor JADX sources and cross-checked against the
 * framing headers of a private HCI capture; payload bytes below are arbitrary
 * fill values, never ciphertext or plaintext from a real session.
 *
 * The component is deliberately independent of the Bluetooth handler and of
 * [S400StandardAuth]: nothing here exercises an end-to-end session.
 */
class S400ChannelCodecTest {

    // ---- decoding: data fragments ----------------------------------------

    @Test
    fun decode_dataFragment_readsLittleEndianSequence() {
        // LE16(seq=5) || payload
        val frame = S400ChannelCodec.decode(hex("0500112233"))
        assertThat(frame).isEqualTo(S400ChannelFrame.Data(5, hex("112233")))
    }

    @Test
    fun decode_dataFragment_acceptsLargestSequence() {
        val frame = S400ChannelCodec.decode(hex("ffffaa"))
        assertThat(frame).isEqualTo(S400ChannelFrame.Data(0xFFFF, hex("aa")))
    }

    @Test
    fun decode_dataFragment_zeroPayloadIsAllowed() {
        val frame = S400ChannelCodec.decode(hex("0100"))
        assertThat(frame).isEqualTo(S400ChannelFrame.Data(1, ByteArray(0)))
    }

    // ---- decoding: control frames ----------------------------------------

    @Test
    fun decode_fragmentStart_matchesCapturedLayout() {
        // 00 00 00 pkg=0D LE16(count=1) — observed "single-frame" ctr control.
        val frame = S400ChannelCodec.decode(hex("0000000d0100"))
        assertThat(frame).isEqualTo(S400ChannelFrame.FragmentStart(packageType = 13, frameCount = 1))
    }

    @Test
    fun decode_fragmentStart_multiFrameCount() {
        val frame = S400ChannelCodec.decode(hex("000000000900"))
        assertThat(frame).isEqualTo(S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 9))
    }

    @Test
    fun decode_ack_withoutResendList() {
        // 00 00 01 status=1  (grant after a fragment start)
        assertThat(S400ChannelCodec.decode(hex("00000101")))
            .isEqualTo(S400ChannelFrame.Ack(status = 1, sequences = emptyList()))
        // status=0 (complete)
        assertThat(S400ChannelCodec.decode(hex("00000100")))
            .isEqualTo(S400ChannelFrame.Ack(status = 0, sequences = emptyList()))
    }

    @Test
    fun decode_ack_withResendList() {
        val frame = S400ChannelCodec.decode(hex("0000010203000500"))
        assertThat(frame).isEqualTo(S400ChannelFrame.Ack(status = 2, sequences = listOf(3, 5)))
    }

    @Test
    fun decode_single_readsPackageTypeAndPayload() {
        val frame = S400ChannelCodec.decode(hex("0000020b00010002"))
        assertThat(frame).isEqualTo(S400ChannelFrame.Single(packageType = 11, payload = hex("00010002")))
    }

    @Test
    fun decode_single_acceptsEmptyPayload() {
        assertThat(S400ChannelCodec.decode(hex("00000200")))
            .isEqualTo(S400ChannelFrame.Single(packageType = 0, payload = ByteArray(0)))
    }

    @Test
    fun decode_singleAck_matchesCapturedLayout() {
        assertThat(S400ChannelCodec.decode(hex("00000300")))
            .isEqualTo(S400ChannelFrame.SingleAck(packageType = 0))
    }

    @Test
    fun decode_managementFrames() {
        assertThat(S400ChannelCodec.decode(hex("0000040006f2")))
            .isEqualTo(S400ChannelFrame.Management(packageType = 0, payload = hex("06f2")))
        assertThat(S400ChannelCodec.decode(hex("0000050106f2")))
            .isEqualTo(S400ChannelFrame.ManagementAck(packageType = 1, payload = hex("06f2")))
    }

    // ---- decoding: rejection of malformed input --------------------------

    @Test
    fun decode_rejectsTooShortValues() {
        assertThat(S400ChannelCodec.decode(ByteArray(0))).isNull()
        assertThat(S400ChannelCodec.decode(hex("00"))).isNull()
        assertThat(S400ChannelCodec.decode(hex("0000"))).isNull()
        assertThat(S400ChannelCodec.decode(hex("000001"))).isNull() // control header truncated
    }

    @Test
    fun decode_rejectsUnknownControlType() {
        assertThat(S400ChannelCodec.decode(hex("00000600"))).isNull()
        assertThat(S400ChannelCodec.decode(hex("0000ff00"))).isNull()
    }

    @Test
    fun decode_rejectsWrongFragmentStartLength() {
        assertThat(S400ChannelCodec.decode(hex("0000000b01"))).isNull()   // 5 bytes
        assertThat(S400ChannelCodec.decode(hex("0000000b010000"))).isNull() // 7 bytes
    }

    @Test
    fun decode_rejectsOddAckBody() {
        assertThat(S400ChannelCodec.decode(hex("0000010003"))).isNull()
    }

    @Test
    fun decode_rejectsOversizedValue() {
        // One byte longer than the largest legal value at the S400's MTU.
        val oversized = S400ChannelCodec.dataFragment(1, ByteArray(S400ChannelCodec.MAX_FRAGMENT_PAYLOAD + 1))
        assertThat(oversized.size).isEqualTo(S400ChannelCodec.MAX_FRAME_VALUE_LENGTH + 1)
        assertThat(S400ChannelCodec.decode(oversized)).isNull()
    }

    @Test
    fun decode_honoursCallerSuppliedFrameLimit() {
        val value = S400ChannelCodec.dataFragment(1, ByteArray(19)) // payload 19 -> value 21
        assertThat(S400ChannelCodec.decode(value, maxFrameLength = 21)).isNotNull()
        assertThat(S400ChannelCodec.decode(value, maxFrameLength = 20)).isNull()
    }

    // ---- MTU-sensitive lengths -------------------------------------------

    @Test
    fun mtuDerivedLengths_matchVendorAndCapture() {
        // ChannelManager.BleChannel: DMTU = mtu - 5, frame value = 2 + DMTU = mtu - 3.
        assertThat(S400ChannelCodec.payloadCapacityForMtu(23)).isEqualTo(18)
        assertThat(S400ChannelCodec.maxFrameValueLengthForMtu(23)).isEqualTo(20)
        assertThat(S400ChannelCodec.payloadCapacityForMtu(247)).isEqualTo(242)
        assertThat(S400ChannelCodec.maxFrameValueLengthForMtu(247)).isEqualTo(244)
        assertThat(S400ChannelCodec.payloadCapacityForMtu(4)).isEqualTo(0)
    }

    @Test
    fun defaultConstants_matchProtocolDefaults() {
        assertThat(S400ChannelCodec.DEFAULT_PAYLOAD_CAPACITY).isEqualTo(18)
        assertThat(S400ChannelCodec.S400_PAYLOAD_CAPACITY).isEqualTo(242)
        assertThat(S400ChannelCodec.MAX_FRAME_VALUE_LENGTH).isEqualTo(244)
        assertThat(S400ChannelCodec.MAX_FRAME_COUNT).isEqualTo(32)
    }

    // ---- encoding: byte-exact layout -------------------------------------

    @Test
    fun encode_fragmentStart_isSixBytesLittleEndian() {
        assertThat(S400ChannelCodec.fragmentStart(0x0B, 1).toHex()).isEqualTo("0000000b0100")
        // The count is a little-endian 16-bit field; 0x20 = 32 is the largest allowed.
        assertThat(S400ChannelCodec.fragmentStart(0x00, 0x20).toHex()).isEqualTo("000000002000")
    }

    @Test
    fun encode_ack_hasStatusThenOptionalResendList() {
        assertThat(S400ChannelCodec.ack(1).toHex()).isEqualTo("00000101")
        assertThat(S400ChannelCodec.ack(0, listOf(3, 5)).toHex()).isEqualTo("0000010003000500")
    }

    @Test
    fun encode_singleAndSingleAck() {
        assertThat(S400ChannelCodec.single(0, hex("010203")).toHex()).isEqualTo("00000200010203")
        assertThat(S400ChannelCodec.singleAck().toHex()).isEqualTo("00000300")
    }

    @Test
    fun encode_managementAndAck() {
        assertThat(S400ChannelCodec.management(0, hex("06f2")).toHex()).isEqualTo("0000040006f2")
        assertThat(S400ChannelCodec.managementAck(1, hex("f2f2")).toHex()).isEqualTo("00000501f2f2")
    }

    @Test
    fun encode_dataFragment_isLittleEndianSequencePrefixed() {
        assertThat(S400ChannelCodec.dataFragment(1, hex("1122")).toHex()).isEqualTo("01001122")
        assertThat(S400ChannelCodec.dataFragment(0x0102, ByteArray(0)).toHex()).isEqualTo("0201")
    }

    @Test(expected = IllegalArgumentException::class)
    fun encode_fragmentStart_rejectsZeroCount() {
        S400ChannelCodec.fragmentStart(0, 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun encode_fragmentStart_rejectsCountAboveLimit() {
        S400ChannelCodec.fragmentStart(0, S400ChannelCodec.MAX_FRAME_COUNT + 1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun encode_dataFragment_rejectsZeroSequence() {
        S400ChannelCodec.dataFragment(0, byteArrayOf(1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun encode_packageTypeOutOfRange() {
        S400ChannelCodec.single(0x100, ByteArray(0))
    }

    // ---- encoding: outgoing fragmentation --------------------------------

    @Test
    fun fragment_singleFrameWhenPayloadFits() {
        val frames = S400ChannelCodec.fragment(packageType = 0, payload = ByteArray(18), capacity = 18)
        assertThat(frames).hasSize(1)
        assertThat(frames[0][2].toInt()).isEqualTo(S400ControlType.SINGLE.code)
        assertThat(frames[0].size).isEqualTo(S400ChannelCodec.CONTROL_HEADER_BYTES + 18)
    }

    @Test
    fun fragment_splitsAtCapacityWithSequentialIndices() {
        val payload = ByteArray(40) { it.toByte() }
        val frames = S400ChannelCodec.fragment(0, payload, capacity = 18)

        // FRAGMENT_START(count = ceil(40 / 18) = 3) + three data frames.
        assertThat(frames).hasSize(4)
        assertThat(S400ChannelCodec.decode(frames[0]))
            .isEqualTo(S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 3))
        assertThat(S400ChannelCodec.decode(frames[1])).isEqualTo(S400ChannelFrame.Data(1, payload.copyOfRange(0, 18)))
        assertThat(S400ChannelCodec.decode(frames[2])).isEqualTo(S400ChannelFrame.Data(2, payload.copyOfRange(18, 36)))
        assertThat(S400ChannelCodec.decode(frames[3])).isEqualTo(S400ChannelFrame.Data(3, payload.copyOfRange(36, 40)))
    }

    @Test
    fun fragment_forceFragmentedKeepsSingleFrameAsControl() {
        val frames = S400ChannelCodec.fragment(7, ByteArray(4), capacity = 18, forceFragmented = true)
        assertThat(frames).hasSize(2)
        assertThat(S400ChannelCodec.decode(frames[0]))
            .isEqualTo(S400ChannelFrame.FragmentStart(packageType = 7, frameCount = 1))
        assertThat(S400ChannelCodec.decode(frames[1])).isEqualTo(S400ChannelFrame.Data(1, ByteArray(4)))
    }

    @Test
    fun fragment_emptyPayloadProducesOneSingleFrame() {
        val frames = S400ChannelCodec.fragment(0, ByteArray(0), capacity = 18)
        assertThat(frames).hasSize(1)
        assertThat(S400ChannelCodec.decode(frames[0]))
            .isEqualTo(S400ChannelFrame.Single(packageType = 0, payload = ByteArray(0)))
    }

    @Test
    fun fragment_framesNeverExceedMtuValueLength() {
        for (capacity in intArrayOf(18, 242)) {
            val payload = ByteArray(capacity * 3 + 5) { (it and 0xFF).toByte() }
            val frames = S400ChannelCodec.fragment(0, payload, capacity = capacity)
            val limit = S400ChannelCodec.maxFrameValueLengthForMtu(capacity + 5)
            frames.forEach { assertThat(it.size).isAtMost(limit) }
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun fragment_rejectsMessagesNeedingTooManyFrames() {
        val payload = ByteArray(S400ChannelCodec.MAX_FRAME_COUNT * 18 + 1)
        S400ChannelCodec.fragment(0, payload, capacity = 18)
    }

    // ---- reassembler: fragmented receive + ack behaviour -----------------

    @Test
    fun reassembler_fragmentStartRequestsContinueAck() {
        val reassembler = S400ChannelReassembler()
        val events = reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelCodec.decode(hex("000000000500"))!!, // ctr, pkg=0, count=5
        )
        assertThat(events).containsExactly(
            S400ChannelEvent.AckRequired(S400ChannelCodec.ACK_STATUS_CONTINUE, emptyList()),
        )
    }

    @Test
    fun reassembler_collectsFragmentsInAnyOrderAndAcksCompletion() {
        val reassembler = S400ChannelReassembler()
        val direction = S400ChannelDirection.DEVICE_TO_APP
        val characteristic = 0x2a

        reassembler.accept(direction, characteristic, S400ChannelFrame.FragmentStart(packageType = 3, frameCount = 3))

        // out-of-order arrival (2, 3, 1) within the declared range is accepted.
        assertThat(reassembler.accept(direction, characteristic, S400ChannelFrame.Data(2, hex("bb")))).isEmpty()
        assertThat(reassembler.accept(direction, characteristic, S400ChannelFrame.Data(3, hex("cc")))).isEmpty()
        val done = reassembler.accept(direction, characteristic, S400ChannelFrame.Data(1, hex("aa")))

        assertThat(done).containsExactly(
            S400ChannelEvent.Message(packageType = 3, payload = hex("aabbcc"), fragmented = true),
            S400ChannelEvent.AckRequired(S400ChannelCodec.ACK_STATUS_COMPLETE, emptyList()),
        )
        assertThat(reassembler.pendingStreamCount).isEqualTo(0)
    }

    @Test
    fun reassembler_singleFrameMessageIsReportedUnfragmented() {
        val reassembler = S400ChannelReassembler()
        val events = reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelCodec.decode(hex("0000020bdeadbeef"))!!,
        )
        assertThat(events).containsExactly(
            S400ChannelEvent.Message(packageType = 11, payload = hex("deadbeef"), fragmented = false),
        )
    }

    // ---- reassembler: stream isolation -----------------------------------

    @Test
    fun reassembler_isolatesDirectionsOnSameCharacteristic() {
        val reassembler = S400ChannelReassembler()
        val characteristic = 0x1e

        reassembler.accept(
            S400ChannelDirection.APP_TO_DEVICE, characteristic,
            S400ChannelFrame.FragmentStart(packageType = 1, frameCount = 2),
        )
        reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, characteristic,
            S400ChannelFrame.FragmentStart(packageType = 2, frameCount = 2),
        )

        assertThat(reassembler.accept(S400ChannelDirection.APP_TO_DEVICE, characteristic, S400ChannelFrame.Data(1, hex("aa")))).isEmpty()
        assertThat(reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, characteristic, S400ChannelFrame.Data(1, hex("bb")))).isEmpty()

        assertThat(reassembler.accept(S400ChannelDirection.APP_TO_DEVICE, characteristic, S400ChannelFrame.Data(2, hex("11"))))
            .contains(S400ChannelEvent.Message(1, hex("aa11"), true))
        assertThat(reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, characteristic, S400ChannelFrame.Data(2, hex("22"))))
            .contains(S400ChannelEvent.Message(2, hex("bb22"), true))
    }

    @Test
    fun reassembler_isolatesCharacteristicsInSameDirection() {
        val reassembler = S400ChannelReassembler()
        val direction = S400ChannelDirection.DEVICE_TO_APP

        reassembler.accept(direction, 0x27, S400ChannelFrame.FragmentStart(packageType = 1, frameCount = 2))
        reassembler.accept(direction, 0x2a, S400ChannelFrame.FragmentStart(packageType = 2, frameCount = 2))

        // A fragment for 0x27 must not complete the 0x2a stream.
        assertThat(reassembler.accept(direction, 0x27, S400ChannelFrame.Data(1, hex("aa")))).isEmpty()
        assertThat(reassembler.accept(direction, 0x2a, S400ChannelFrame.Data(1, hex("bb")))).isEmpty()
        assertThat(reassembler.accept(direction, 0x2a, S400ChannelFrame.Data(2, hex("22"))))
            .contains(S400ChannelEvent.Message(2, hex("bb22"), true))
        assertThat(reassembler.accept(direction, 0x27, S400ChannelFrame.Data(2, hex("11"))))
            .contains(S400ChannelEvent.Message(1, hex("aa11"), true))
    }

    // ---- reassembler: bounded / robust rejection -------------------------

    @Test
    fun reassembler_rejectsStrayFragment() {
        val reassembler = S400ChannelReassembler()
        val events = reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.Data(1, hex("aa")),
        )
        assertThat(events).hasSize(1)
        assertThat((events[0] as S400ChannelEvent.Rejected).reason).contains("without a fragment-start")
    }

    @Test
    fun reassembler_rejectsSequenceAboveDeclaredCount() {
        val reassembler = S400ChannelReassembler()
        reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 2),
        )
        val events = reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, 0x2a, S400ChannelFrame.Data(3, hex("aa")))
        assertThat((events.single() as S400ChannelEvent.Rejected).reason).contains("sequence out of range")
        assertThat(reassembler.pendingStreamCount).isEqualTo(0)
    }

    @Test
    fun reassembler_rejectsDuplicateFragment() {
        val reassembler = S400ChannelReassembler()
        reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 3),
        )
        assertThat(reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, 0x2a, S400ChannelFrame.Data(1, hex("aa")))).isEmpty()
        val events = reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, 0x2a, S400ChannelFrame.Data(1, hex("aa")))
        assertThat((events.single() as S400ChannelEvent.Rejected).reason).contains("duplicate")
    }

    @Test
    fun reassembler_rejectsUnboundedFragmentCount() {
        val reassembler = S400ChannelReassembler()
        val events = reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.FragmentStart(packageType = 0, frameCount = S400ChannelCodec.MAX_FRAME_COUNT + 1),
        )
        assertThat((events.single() as S400ChannelEvent.Rejected).reason).contains("frameCount out of range")
        assertThat(reassembler.pendingStreamCount).isEqualTo(0)
    }

    @Test
    fun reassembler_rejectsZeroFragmentCount() {
        val reassembler = S400ChannelReassembler()
        val events = reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 0),
        )
        assertThat(events.single()).isInstanceOf(S400ChannelEvent.Rejected::class.java)
    }

    @Test
    fun reassembler_rejectsOversizedFragmentAndClearsStream() {
        val reassembler = S400ChannelReassembler()
        reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 2),
        )
        val oversized = S400ChannelFrame.Data(1, ByteArray(S400ChannelCodec.MAX_FRAGMENT_PAYLOAD + 1))
        val events = reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, 0x2a, oversized)
        assertThat((events.single() as S400ChannelEvent.Rejected).reason).contains("exceeds")
        assertThat(reassembler.pendingStreamCount).isEqualTo(0)
    }

    @Test
    fun reassembler_resetDropsPartialState() {
        val reassembler = S400ChannelReassembler()
        reassembler.accept(
            S400ChannelDirection.DEVICE_TO_APP, 0x2a,
            S400ChannelFrame.FragmentStart(packageType = 0, frameCount = 2),
        )
        assertThat(reassembler.pendingStreamCount).isEqualTo(1)
        reassembler.reset(S400ChannelDirection.DEVICE_TO_APP, 0x2a)
        assertThat(reassembler.pendingStreamCount).isEqualTo(0)
        assertThat(reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, 0x2a, S400ChannelFrame.Data(1, hex("aa"))).single())
            .isInstanceOf(S400ChannelEvent.Rejected::class.java)
    }

    // ---- reassembler: pass-through control frames ------------------------

    @Test
    fun reassembler_passesAckAndManagementFramesThrough() {
        val reassembler = S400ChannelReassembler()
        val direction = S400ChannelDirection.DEVICE_TO_APP

        assertThat(reassembler.accept(direction, 0x2a, S400ChannelFrame.Ack(1, emptyList())))
            .containsExactly(S400ChannelEvent.Ack(1, emptyList()))
        assertThat(reassembler.accept(direction, 0x1e, S400ChannelFrame.SingleAck(0))).isEmpty()
        assertThat(reassembler.accept(direction, 0x1e, S400ChannelFrame.Management(0, hex("06f2"))))
            .containsExactly(S400ChannelEvent.Management(0, hex("06f2"), acknowledgement = false))
        assertThat(reassembler.accept(direction, 0x1e, S400ChannelFrame.ManagementAck(1, hex("f2f2"))))
            .containsExactly(S400ChannelEvent.Management(1, hex("f2f2"), acknowledgement = true))
    }

    // ---- end-to-end envelope loop (codec only, no crypto/no handler) -----

    @Test
    fun encodeFragmentDecodeReassemble_roundTripsAtDefaultCapacity() {
        val payload = ByteArray(100) { (it * 7 + 1).toByte() }
        val frames = S400ChannelCodec.fragment(packageType = 42, payload = payload, capacity = 18)

        val reassembler = S400ChannelReassembler()
        val direction = S400ChannelDirection.APP_TO_DEVICE
        val characteristic = 0x27

        var message: S400ChannelEvent.Message? = null
        for (raw in frames) {
            val decoded = S400ChannelCodec.decode(raw)!!
            for (event in reassembler.accept(direction, characteristic, decoded)) {
                if (event is S400ChannelEvent.Message) message = event
            }
        }
        assertThat(message).isNotNull()
        assertThat(message!!.packageType).isEqualTo(42)
        assertThat(message.fragmented).isTrue()
        assertThat(message.payload).isEqualTo(payload)
    }

    @Test
    fun encodeFragmentDecodeReassemble_roundTripsAtS400Capacity() {
        // 242-byte capacity, message spanning three frames, delivered shuffled.
        val payload = ByteArray(600) { (it and 0xFF).toByte() }
        val frames = S400ChannelCodec.fragment(packageType = 0, payload = payload, capacity = 242)
        assertThat(frames).hasSize(4) // start + 3 fragments

        val reassembler = S400ChannelReassembler()
        val direction = S400ChannelDirection.APP_TO_DEVICE
        val characteristic = 0x27

        val start = S400ChannelCodec.decode(frames[0]) as S400ChannelFrame.FragmentStart
        assertThat(start.frameCount).isEqualTo(3)
        assertThat(reassembler.accept(direction, characteristic, start))
            .containsExactly(S400ChannelEvent.AckRequired(S400ChannelCodec.ACK_STATUS_CONTINUE, emptyList()))

        val fragments = frames.drop(1).map { S400ChannelCodec.decode(it) as S400ChannelFrame.Data }
        var message: S400ChannelEvent.Message? = null
        for (fragment in listOf(fragments[2], fragments[0], fragments[1])) {
            for (event in reassembler.accept(direction, characteristic, fragment)) {
                if (event is S400ChannelEvent.Message) message = event
            }
        }
        assertThat(message).isNotNull()
        assertThat(message!!.payload).isEqualTo(payload)
    }

    private fun hex(text: String): ByteArray {
        require(text.length % 2 == 0) { "hex string must have even length" }
        return ByteArray(text.length / 2) { i ->
            ((Character.digit(text[i * 2], 16) shl 4) or Character.digit(text[i * 2 + 1], 16)).toByte()
        }
    }

    private fun ByteArray.toHex(): String {
        val out = StringBuilder(size * 2)
        for (b in this) out.append("%02x".format(b.toInt() and 0xFF))
        return out.toString()
    }
}
