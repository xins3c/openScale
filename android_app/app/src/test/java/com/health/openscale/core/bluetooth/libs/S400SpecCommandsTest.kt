/*
 * openScale
 * Copyright (C) 2025 olie.xdev <olie.xdeveloper@googlemail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.health.openscale.core.bluetooth.libs

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Synthetic vectors for [S400SpecCommands].
 *
 * The expected byte strings here were produced by an independent reference
 * implementation of the same documented layout, and that reference was first
 * checked byte-for-byte against real decrypted S400 Spec-channel traffic
 * (the 30-byte 6.6 and 36-byte 6.5 frames, plus the fixed prefix of the
 * 120-byte 13.1 frame). No captured device/account/health value appears in
 * this file: every input below is synthetic.
 */
class S400SpecCommandsTest {

    private fun hex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            out.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0F])
        }
        return out.toString()
    }

    // ---- verified action frames -------------------------------------------

    @Test fun switchUserFrameIsExactlyThirtyBytes() {
        // 6.6 genSwitchUserSpec: siid 6, aiid 6, count 3, piid order 1, 8, 4.
        val frame = S400SpecCommands.switchUserFrame(sequence = 1, miid = 1234567890L,
            uid = 2, userType = 1)
        assertThat(frame.size).isEqualTo(30)
        assertThat(hex(frame)).isEqualTo(
            "1e2001000506060301000880d20296490000000008000110020400011001"
        )
    }

    @Test fun basicWeightFrameIsExactlyThirtySixBytes() {
        // 6.5 genBasicWeightSpec: 6.6 plus piid 6 UINT16 weight in 100 g units.
        val frame = S400SpecCommands.basicWeightFrame(sequence = 2, miid = 1234567890L,
            uid = 2, userType = 1, weight100g = 873)
        assertThat(frame.size).isEqualTo(36)
        assertThat(hex(frame)).isEqualTo(
            "242002000506050401000880d20296490000000008000110020400011001060002306903"
        )
    }

    @Test fun deleteUserFrameSharesTheSwitchUserLayout() {
        // genDeleteUserSpec -> aiid 3, same three properties -> same size.
        val frame = S400SpecCommands.encodeActionFrame(sequence = 3,
            siid = S400SpecCommands.SIID_USER, aiid = S400SpecCommands.AIID_USER_DELETE,
            properties = S400SpecCommands.deleteUser(1234567890L, 2, 1))
        assertThat(frame.size).isEqualTo(30)
        assertThat(hex(frame)).isEqualTo(
            "1e2003000506030301000880d20296490000000008000110020400011001"
        )
    }

    // ---- 13.1 device / user sync ------------------------------------------

    @Test fun deviceSyncHeaderAndPropertyOrderMatchCapture() {
        // The first 26 bytes are value-independent; only the STRING body varies.
        // Compare against the decrypted 13.1 frame prefix.
        val users = listOf(S400SpecCommands.UserRow(
            uid = 2, userType = 1, age = 30, sex = 1, heightCm = 170,
            targetWeight100g = 650, updatedAtEpochSeconds = 1792038000L))
        val json = S400SpecCommands.userSyncJson(
            mid = "1234567890", masterUid = 2, userCount = 1, isOwner = true,
            hash = S400SpecCommands.userSyncHash(users), users = users)
        val frame = S400SpecCommands.deviceSyncFrame(sequence = 8, appVersion = 31, unit = 1,
            timestampEpochSeconds = 1792038948L, isOn = true, json = json)
        // header: len|0x2000, seq, op 5, siid 13, aiid 1, count 5
        assertThat(hex(frame.copyOfRange(0, 8))).isEqualTo("c5200800050d0105")
        // piid/desc for the first three properties, in the bundle's order 1,2,4
        assertThat(hex(frame.copyOfRange(8, 27)))
            .isEqualTo("010002301f000200011001040004502458d06a")
        // then piid 3 BOOL and piid 5 STRING descriptor (0xA054 == STRING/84)
        assertThat(hex(frame.copyOfRange(27, 32))).isEqualTo("0300010001")
    }

    @Test fun deviceSyncLengthsFollowUserCount() {
        val none = S400SpecCommands.deviceSyncFrame(9, 31, 1, 1792038948L, true,
            S400SpecCommands.userSyncJson("1234567890", 2, 2, true,
                "746927cfbbad758f7d05e05d880249b6", null))
        assertThat(none.size).isEqualTo(120)

        val one = listOf(S400SpecCommands.UserRow(2, 1, 30, 1, 170, 650, 1792038000L))
        val oneFrame = S400SpecCommands.deviceSyncFrame(8, 31, 1, 1792038948L, true,
            S400SpecCommands.userSyncJson("1234567890", 2, 1, true,
                S400SpecCommands.userSyncHash(one), one))
        assertThat(oneFrame.size).isEqualTo(197)

        val two = one + S400SpecCommands.UserRow(3, 0, 41, 2, 181, 720, 1792038100L)
        val twoFrame = S400SpecCommands.deviceSyncFrame(7, 31, 1, 1792038948L, true,
            S400SpecCommands.userSyncJson("1234567890", 2, 2, true,
                S400SpecCommands.userSyncHash(two), two))
        assertThat(twoFrame.size).isEqualTo(267)
    }

    // ---- JSON / hash model -------------------------------------------------

    @Test fun userRowJsonMatchesBundleKeyOrder() {
        val row = S400SpecCommands.UserRow(2, 1, 30, 1, 170, 650, 1792038000L)
        assertThat(row.toJson())
            .isEqualTo("{\"uid\":2,\"ut\":1,\"age\":30,\"sex\":1,\"hi\":170,\"wt\":650,\"time\":1792038000}")
    }

    @Test fun userSyncHashIsCompactArrayMd5() {
        val users = listOf(
            S400SpecCommands.UserRow(2, 1, 30, 1, 170, 650, 1792038000L),
            S400SpecCommands.UserRow(3, 0, 41, 2, 181, 720, 1792038100L),
        )
        // md5('[{"uid":2,...},{"uid":3,...}]') — verified against the decrypted
        // 273-byte frame's own hash field during the investigation.
        assertThat(S400SpecCommands.userSyncHash(users))
            .isEqualTo("746927cfbbad758f7d05e05d880249b6")
    }

    @Test fun userSyncJsonOmitsUdWhenAbsent() {
        val json = S400SpecCommands.userSyncJson(
            mid = "1234567890", masterUid = 2, userCount = 2, isOwner = true,
            hash = "746927cfbbad758f7d05e05d880249b6", users = null)
        assertThat(json).isEqualTo(
            "{\"mid\":\"1234567890\",\"uid\":2,\"uc\":2,\"ow\":1," +
                "\"hash\":\"746927cfbbad758f7d05e05d880249b6\"}"
        )
        assertThat(json.toByteArray(Charsets.UTF_8).size).isEqualTo(84)
    }

    @Test fun ownerFlagMapsToInteger() {
        val owner = S400SpecCommands.userSyncJson("1", 2, 0, true, "aa", null)
        val guest = S400SpecCommands.userSyncJson("1", 2, 0, false, "aa", null)
        assertThat(owner).contains("\"ow\":1")
        assertThat(guest).contains("\"ow\":0")
    }

    // ---- descriptor words and encoders ------------------------------------

    @Test fun descriptorWordEncodesTypeAndLength() {
        fun desc(p: S400SpecCommands.Property): String =
            hex(S400SpecCommands.encodeProperty(p).copyOfRange(2, 4))
        assertThat(desc(S400SpecCommands.Property.Int64(1, 1))).isEqualTo("0880")   // 0x8008
        assertThat(desc(S400SpecCommands.Property.UInt8(8, 1))).isEqualTo("0110")   // 0x1001
        assertThat(desc(S400SpecCommands.Property.UInt16(6, 1))).isEqualTo("0230")  // 0x3002
        assertThat(desc(S400SpecCommands.Property.UInt32(4, 1))).isEqualTo("0450")  // 0x5004
        assertThat(desc(S400SpecCommands.Property.Bool(3, true))).isEqualTo("0100") // 0x0001
        assertThat(desc(S400SpecCommands.Property.Text(5, "{}"))).isEqualTo("02a0") // 0xa002
    }

    @Test fun propertyEncodesPiidLittleEndianThenValue() {
        assertThat(hex(S400SpecCommands.encodeProperty(S400SpecCommands.Property.Int64(1, 1234567890L))))
            .isEqualTo("01000880d202964900000000")
        assertThat(hex(S400SpecCommands.encodeProperty(S400SpecCommands.Property.UInt16(6, 873))))
            .isEqualTo("060002306903")
        assertThat(hex(S400SpecCommands.encodeProperty(S400SpecCommands.Property.Bool(13, true))))
            .isEqualTo("0d00010001")
    }

    @Test fun actionBodyPreservesGivenPropertyOrder() {
        val body = S400SpecCommands.encodeActionBody(13, 1, listOf(
            S400SpecCommands.Property.UInt16(1, 31),
            S400SpecCommands.Property.UInt8(2, 1),
            S400SpecCommands.Property.UInt32(4, 1),
            S400SpecCommands.Property.Bool(3, true),
            S400SpecCommands.Property.Text(5, "{}")))
        // siid, aiid, count then piids 1, 2, 4, 3, 5 — NOT sorted.
        assertThat(body[0].toInt()).isEqualTo(13)
        assertThat(body[1].toInt()).isEqualTo(1)
        assertThat(body[2].toInt()).isEqualTo(5)
        val piids = mutableListOf<Int>()
        var i = 3
        while (i < body.size) {
            piids.add((body[i].toInt() and 0xFF) or ((body[i + 1].toInt() and 0xFF) shl 8))
            val len = ((body[i + 2].toInt() and 0xFF) or ((body[i + 3].toInt() and 0xFF) shl 8)) and 0x0FFF
            i += 4 + len
        }
        assertThat(piids).containsExactly(1, 2, 4, 3, 5).inOrder()
    }

    @Test fun frameCarriesLittleEndianLengthAndSequence() {
        val frame = S400SpecCommands.switchUserFrame(0x1234, 1L, 1, 1)
        assertThat(frame[0].toInt() and 0xFF).isEqualTo(0x1e)
        assertThat(frame[1].toInt() and 0xFF).isEqualTo(0x20)
        assertThat(frame[2].toInt() and 0xFF).isEqualTo(0x34)
        assertThat(frame[3].toInt() and 0xFF).isEqualTo(0x12)
        assertThat(frame[4].toInt()).isEqualTo(5)
    }

    // ---- guards ------------------------------------------------------------

    @Test fun rejectsDuplicatePiidAndBadSiid() {
        runCatching {
            S400SpecCommands.encodeActionBody(6, 6, listOf(
                S400SpecCommands.Property.UInt8(1, 1),
                S400SpecCommands.Property.UInt8(1, 2)))
        }.onSuccess { throw AssertionError("duplicate piid accepted") }

        runCatching { S400SpecCommands.encodeActionBody(0, 6, emptyList()) }
            .onSuccess { throw AssertionError("siid 0 accepted") }
        runCatching { S400SpecCommands.encodeActionBody(6, 256, emptyList()) }
            .onSuccess { throw AssertionError("aiid 256 accepted") }
    }

    @Test fun rejectsOversizedString() {
        val big = "x".repeat(S400SpecCommands.MAX_STRING_BYTES + 1)
        runCatching { S400SpecCommands.encodeProperty(S400SpecCommands.Property.Text(5, big)) }
            .onSuccess { throw AssertionError("oversized string accepted") }
    }

    // ---- setProperties (source-verified only) ------------------------------

    @Test fun enterModeFrameIsTwelveBytes() {
        // devEnterMode: {objects:[{siid:10, piid:1, value:mode, type:1}]}
        // Header is len(2) seq(2) op(1) count(1) == 6, plus 6 per entry.
        val frame = S400SpecCommands.enterModeFrame(0x10, 2)
        assertThat(frame.size).isEqualTo(12)
        assertThat(hex(frame)).isEqualTo("0c20100000010a0100011002")
    }

    @Test fun setPropertiesCarriesPerPropertySiid() {
        val frame = S400SpecCommands.encodeSetPropertiesFrame(1, listOf(
            S400SpecCommands.WriteProperty(2, 2, S400SpecCommands.ValueType.UINT8, 0),
            S400SpecCommands.WriteProperty(2, 1, S400SpecCommands.ValueType.UINT8, 1),
        ))
        assertThat(frame[4].toInt()).isEqualTo(S400SpecCommands.OP_SET_PROPERTIES)
        assertThat(frame[5].toInt()).isEqualTo(2)          // count
        // entry 1 occupies 6..11: siid(6) piid(7..8) desc(9..10) value(11)
        assertThat(frame[6].toInt()).isEqualTo(2)          // siid
        assertThat(frame[7].toInt() and 0xFF).isEqualTo(2) // piid LE
        // entry 2 occupies 12..17
        assertThat(frame[12].toInt()).isEqualTo(2)         // second entry siid
        assertThat(frame[13].toInt() and 0xFF).isEqualTo(1)
        assertThat(frame[11].toInt()).isEqualTo(0)         // first value
        assertThat(frame[17].toInt()).isEqualTo(1)         // second value
    }

    @Test fun setPropertiesRejectsDuplicateSiidPiid() {
        runCatching {
            S400SpecCommands.encodeSetPropertiesBody(listOf(
                S400SpecCommands.WriteProperty(2, 1, S400SpecCommands.ValueType.UINT8, 0),
                S400SpecCommands.WriteProperty(2, 1, S400SpecCommands.ValueType.UINT8, 1)))
        }.onSuccess { throw AssertionError("duplicate siid/piid accepted") }
    }

    @Test fun bootstrapControlFrameIsUnchanged() {
        // Regression guard: the control frame layout already shipped in
        // S400SpecProtocol must stay exactly as verified.
        assertThat(hex(S400SpecProtocol.bootstrap(0x0015)))
            .isEqualTo("05201500f0")
    }
}
