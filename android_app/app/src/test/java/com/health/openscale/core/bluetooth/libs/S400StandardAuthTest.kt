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
 * Unit tests for [S400StandardAuth] / [S400StandardAuthSession].
 *
 * Every value below is a synthetic, fixed constant: there is no real device
 * token, session key, MAC address or health payload anywhere in this file. The
 * expected outputs were produced by an independent implementation of the same
 * protocol (HKDF-SHA256 / HMAC-SHA256 / AES-CCM) and pin the byte-exact
 * behaviour of the component.
 */
class S400StandardAuthTest {

    private companion object {
        // Synthetic fixed inputs (NOT secrets).
        const val TOKEN_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        const val APP_RANDOM_HEX = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        const val DEV_RANDOM_HEX = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"

        const val SESSION_KEY_HEX =
            "b073be37c9d8564a2ca5736556409dc9b7fcf840e74e016ac698370ba06d38e3" +
                "068b9f8e057a6a02c1bac49a146b11974e442180f5778395ab8305f1fd4d601b"
        const val SK_RX_KEY_HEX = "b073be37c9d8564a2ca5736556409dc9"
        const val SK_TX_KEY_HEX = "b7fcf840e74e016ac698370ba06d38e3"
        const val SK_RX_PREFIX_HEX = "068b9f8e"
        const val SK_TX_PREFIX_HEX = "057a6a02"

        const val DEVICE_CONFIRM_HEX =
            "83de3465de59074f854f21b980de86eb8b140675b324959057cf0d679dc600a2"
        const val APP_CONFIRM_HEX =
            "64811569875c8887d93f0490e53d189ed104cea9cd0b6c0fde55b47eb02759d8"

        // TX vector: counter 0x00010002, plaintext "S400 StandardAuth vector 0001"
        const val TX_COUNTER = 0x00010002
        const val TX_PLAINTEXT_HEX = "53343030205374616e646172644175746820766563746f722030303031"
        const val TX_NONCE_HEX = "057a6a020000000002000100"
        const val TX_FRAME_HEX =
            "0200b4780300cff870de7a4ede8282bcf41cb51a7065f929a4ab0e06f426027581deae"

        // RX vector: counter 0x00000005, plaintext "S400 StandardAuth vector 0002"
        const val RX_COUNTER = 0x00000005
        const val RX_PLAINTEXT_HEX = "53343030205374616e646172644175746820766563746f722030303032"
        const val RX_NONCE_HEX = "068b9f8e0000000005000000"
        const val RX_FRAME_HEX =
            "05006fd80bf2ba14bc4a5223828000506b778e66ebb0e72e859b0d2db9622fbefc03e9"

        // RX vector with a non-zero counter high word (0x00030004)
        const val RX_HIGH_COUNTER_HIGH = 0x0003
        const val RX_HIGH_PLAINTEXT_HEX = "53343030205374616e646172644175746820766563746f722030303033"
        const val RX_HIGH_FRAME_HEX =
            "04001ac053ea1266aafab4a1d09154c04fa62394f6e0834c8268d6b5812980e351971b"
    }

    private val token = TOKEN_HEX.toByteArrayHex()
    private val appRandom = APP_RANDOM_HEX.toByteArrayHex()
    private val devRandom = DEV_RANDOM_HEX.toByteArrayHex()
    private val sessionKey = SESSION_KEY_HEX.toByteArrayHex()

    // ---- session key derivation -----------------------------------------

    @Test
    fun deriveSessionKey_matchesDeterministicVector() {
        val derived = S400StandardAuth.deriveSessionKey(token, appRandom, devRandom)
        assertThat(derived.toHex()).isEqualTo(SESSION_KEY_HEX)
        assertThat(derived.size).isEqualTo(S400StandardAuth.SESSION_KEY_LENGTH)
    }

    @Test
    fun deriveSessionKey_isDeterministic() {
        val first = S400StandardAuth.deriveSessionKey(token, appRandom, devRandom)
        val second = S400StandardAuth.deriveSessionKey(token, appRandom, devRandom)
        assertThat(first).isEqualTo(second)
    }

    @Test
    fun deriveSessionKey_swappingRandomsChangesSalt() {
        val a = S400StandardAuth.deriveSessionKey(token, appRandom, devRandom)
        val b = S400StandardAuth.deriveSessionKey(token, devRandom, appRandom)
        assertThat(a.toHex()).isNotEqualTo(b.toHex())
    }

    @Test
    fun sessionKeyLayout_hasExpectedSlices() {
        assertThat(sessionKey.copyOfRange(0, 16).toHex()).isEqualTo(SK_RX_KEY_HEX)
        assertThat(sessionKey.copyOfRange(16, 32).toHex()).isEqualTo(SK_TX_KEY_HEX)
        assertThat(sessionKey.copyOfRange(32, 36).toHex()).isEqualTo(SK_RX_PREFIX_HEX)
        assertThat(sessionKey.copyOfRange(36, 40).toHex()).isEqualTo(SK_TX_PREFIX_HEX)
    }

    @Test(expected = IllegalArgumentException::class)
    fun deriveSessionKey_rejectsEmptyToken() {
        S400StandardAuth.deriveSessionKey(ByteArray(0), appRandom, devRandom)
    }

    @Test(expected = IllegalArgumentException::class)
    fun deriveSessionKey_rejectsWrongRandomLength() {
        S400StandardAuth.deriveSessionKey(token, ByteArray(8), devRandom)
    }

    // ---- confirmations ---------------------------------------------------

    @Test
    fun deviceConfirmation_matchesVector() {
        val confirm = S400StandardAuth.deviceConfirmation(sessionKey, appRandom, devRandom)
        assertThat(confirm.toHex()).isEqualTo(DEVICE_CONFIRM_HEX)
        assertThat(confirm.size).isEqualTo(S400StandardAuth.CONFIRMATION_LENGTH)
    }

    @Test
    fun appConfirmation_matchesVector() {
        val confirm = S400StandardAuth.appConfirmation(sessionKey, appRandom, devRandom)
        assertThat(confirm.toHex()).isEqualTo(APP_CONFIRM_HEX)
        assertThat(confirm.size).isEqualTo(S400StandardAuth.CONFIRMATION_LENGTH)
    }

    @Test
    fun deviceAndAppConfirmation_useDifferentHalves() {
        val dev = S400StandardAuth.deviceConfirmation(sessionKey, appRandom, devRandom)
        val app = S400StandardAuth.appConfirmation(sessionKey, appRandom, devRandom)
        assertThat(dev.toHex()).isNotEqualTo(app.toHex())
    }

    @Test
    fun confirmationsMatch_acceptsCorrectRejectsTampered() {
        val expected = S400StandardAuth.appConfirmation(sessionKey, appRandom, devRandom)
        assertThat(S400StandardAuth.confirmationsMatch(expected, expected.copyOf())).isTrue()

        val tampered = expected.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertThat(S400StandardAuth.confirmationsMatch(expected, tampered)).isFalse()

        assertThat(S400StandardAuth.confirmationsMatch(expected, expected.copyOfRange(0, 31))).isFalse()
    }

    // ---- nonce / counter framing ----------------------------------------

    @Test
    fun buildNonce_matchesVectors() {
        val txNonce = S400StandardAuth.buildNonce(sessionKey.copyOfRange(36, 40), TX_COUNTER)
        assertThat(txNonce.toHex()).isEqualTo(TX_NONCE_HEX)

        val rxNonce = S400StandardAuth.buildNonce(sessionKey.copyOfRange(32, 36), RX_COUNTER)
        assertThat(rxNonce.toHex()).isEqualTo(RX_NONCE_HEX)
        assertThat(txNonce.size).isEqualTo(S400StandardAuth.NONCE_LENGTH)
    }

    @Test
    fun counterPrefix_isLittleEndian() {
        assertThat(S400StandardAuth.counterPrefix(0x00010002).toHex()).isEqualTo("0200")
        assertThat(S400StandardAuth.counterPrefix(0x0102).toHex()).isEqualTo("0201")
    }

    // ---- AES-CCM transport ----------------------------------------------

    @Test
    fun encryptFrame_matchesVector() {
        val frame = S400StandardAuth.encryptFrame(sessionKey, TX_PLAINTEXT_HEX.toByteArrayHex(), TX_COUNTER)
        assertThat(frame.toHex()).isEqualTo(TX_FRAME_HEX)
    }

    @Test
    fun decryptFrame_matchesVector() {
        val plaintext = S400StandardAuth.decryptFrame(sessionKey, RX_FRAME_HEX.toByteArrayHex(), 0)
        assertThat(plaintext).isNotNull()
        assertThat(plaintext!!.toHex()).isEqualTo(RX_PLAINTEXT_HEX)
    }

    @Test
    fun decryptFrame_withNonZeroCounterHighWord_matchesVector() {
        val plaintext = S400StandardAuth.decryptFrame(
            sessionKey, RX_HIGH_FRAME_HEX.toByteArrayHex(), RX_HIGH_COUNTER_HIGH
        )
        assertThat(plaintext).isNotNull()
        assertThat(plaintext!!.toHex()).isEqualTo(RX_HIGH_PLAINTEXT_HEX)
        // the same frame must fail when the high word is wrong
        assertThat(S400StandardAuth.decryptFrame(sessionKey, RX_HIGH_FRAME_HEX.toByteArrayHex(), 0)).isNull()
    }

    @Test
    fun encryptThenDecrypt_roundTrips() {
        val plaintext = "S400 round-trip payload".toByteArray(Charsets.US_ASCII)
        val frame = S400StandardAuth.encryptFrame(sessionKey, plaintext, 0x00000007)
        // app->device frame is keyed with SK[16:32]; decrypt it with that half
        val opened = S400StandardAuth.decryptFrame(
            ByteArray(64).also {
                System.arraycopy(sessionKey, 16, it, 0, 16)   // RX key  = TX key
                System.arraycopy(sessionKey, 36, it, 32, 4)   // RX pfx  = TX pfx
            },
            frame,
            0
        )
        assertThat(opened).isEqualTo(plaintext)
    }

    // ---- rejection / tamper handling ------------------------------------

    @Test
    fun decryptFrame_rejectsTamperedTag() {
        val frame = RX_FRAME_HEX.toByteArrayHex()
        frame[frame.size - 1] = (frame[frame.size - 1].toInt() xor 0x01).toByte()
        assertThat(S400StandardAuth.decryptFrame(sessionKey, frame, 0)).isNull()
    }

    @Test
    fun decryptFrame_rejectsTamperedCiphertext() {
        val frame = RX_FRAME_HEX.toByteArrayHex()
        frame[3] = (frame[3].toInt() xor 0x01).toByte()
        assertThat(S400StandardAuth.decryptFrame(sessionKey, frame, 0)).isNull()
    }

    @Test
    fun decryptFrame_rejectsWrongCounter() {
        // Nonce is bound to the low counter word carried in the frame prefix.
        val frame = RX_FRAME_HEX.toByteArrayHex()
        frame[0] = (frame[0].toInt() xor 0x01).toByte()
        assertThat(S400StandardAuth.decryptFrame(sessionKey, frame, 0)).isNull()
    }

    @Test
    fun decryptFrame_rejectsWrongSessionKey() {
        val wrongKey = ByteArray(64) { 0x5A }
        assertThat(S400StandardAuth.decryptFrame(wrongKey, RX_FRAME_HEX.toByteArrayHex(), 0)).isNull()
    }

    @Test
    fun decryptFrame_rejectsTruncatedFrame() {
        assertThat(S400StandardAuth.decryptFrame(sessionKey, byteArrayOf(0x05, 0x00), 0)).isNull()
        assertThat(S400StandardAuth.decryptFrame(sessionKey, ByteArray(0), 0)).isNull()
    }

    @Test(expected = IllegalArgumentException::class)
    fun decryptFrame_rejectsWrongKeyLength() {
        S400StandardAuth.decryptFrame(ByteArray(16), RX_FRAME_HEX.toByteArrayHex(), 0)
    }

    // ---- stateful session / counter carry -------------------------------

    @Test
    fun session_counterAdvancesPerFrame() {
        val session = S400StandardAuthSession(sessionKey)
        val first = session.encrypt("one".toByteArray(Charsets.US_ASCII))
        val second = session.encrypt("two".toByteArray(Charsets.US_ASCII))
        assertThat(first.toHex().substring(0, 4)).isEqualTo("0000")
        assertThat(second.toHex().substring(0, 4)).isEqualTo("0100")
        assertThat(session.appCounter).isEqualTo(2)
    }

    @Test
    fun session_decryptRejectsReplayAndTamperWithoutMovingCounter() {
        val session = S400StandardAuthSession(sessionKey)
        val first = rxFrame(5)
        assertThat(session.decrypt(first)).isEqualTo(byteArrayOf(0x41))
        assertThat(session.deviceCounterLow).isEqualTo(5)
        assertThat(session.decrypt(first)).isNull()
        assertThat(session.deviceCounterLow).isEqualTo(5)
        val bad = rxFrame(6).also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThat(session.decrypt(bad)).isNull()
        assertThat(session.deviceCounterLow).isEqualTo(5)
        assertThat(session.decrypt(rxFrame(6))).isEqualTo(byteArrayOf(0x41))
        assertThat(session.deviceCounterLow).isEqualTo(6)
    }

    @Test
    fun session_decryptCarriesOnAuthenticatedBit15Crossings() {
        val session = S400StandardAuthSession(sessionKey)
        assertThat(session.decrypt(rxFrame(0x7FFF))).isNotNull()
        assertThat(session.deviceCounterHigh).isEqualTo(0)
        assertThat(session.decrypt(rxFrame(0x8000, 1))).isNotNull()
        assertThat(session.deviceCounterHigh).isEqualTo(1)
        assertThat(session.decrypt(rxFrame(0xFFFF, 1))).isNotNull()
        assertThat(session.deviceCounterHigh).isEqualTo(1)
        assertThat(session.decrypt(rxFrame(0, 2))).isNotNull()
        assertThat(session.deviceCounterHigh).isEqualTo(2)
    }

    @Test
    fun session_encryptCarriesAtBothBit15Crossings() {
        val session = S400StandardAuthSession(sessionKey)
        val field = S400StandardAuthSession::class.java.getDeclaredField("appCounter")
        field.isAccessible = true
        field.setInt(session, 0x7FFF)
        assertThat(session.encrypt(byteArrayOf(0x41)).take(2).toByteArray()).isEqualTo(byteArrayOf(0xFF.toByte(), 0x7F))
        assertThat(session.appCounter).isEqualTo(0x18000)
        field.setInt(session, 0x1FFFF)
        session.encrypt(byteArrayOf(0x41))
        assertThat(session.appCounter).isEqualTo(0x20000)
    }

    private fun rxFrame(low: Int, high: Int = 0): ByteArray {
        val key = sessionKey.copyOf()
        System.arraycopy(sessionKey, 0, key, 16, 16)
        System.arraycopy(sessionKey, 32, key, 36, 4)
        return S400StandardAuth.encryptFrame(key, byteArrayOf(0x41), (high shl 16) or low)
    }
}

private fun String.toByteArrayHex(): ByteArray {
    require(length % 2 == 0) { "hex string must have even length" }
    return ByteArray(length / 2) { i ->
        ((Character.digit(this[i * 2], 16) shl 4) or Character.digit(this[i * 2 + 1], 16)).toByte()
    }
}

private fun ByteArray.toHex(): String {
    val out = StringBuilder(size * 2)
    for (b in this) out.append("%02x".format(b.toInt() and 0xFF))
    return out.toString()
}
