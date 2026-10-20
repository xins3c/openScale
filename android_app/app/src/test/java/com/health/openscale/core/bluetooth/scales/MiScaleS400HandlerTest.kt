/*
 * openScale
 * Copyright (C) 2026 openScale contributors
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
package com.health.openscale.core.bluetooth.scales

import com.google.common.truth.Truth.assertThat
import com.health.openscale.core.bluetooth.ScaleCatalog.hex
import com.health.openscale.core.bluetooth.ScaleCatalog.uuid16
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.bluetooth.libs.S400ChannelCodec
import com.health.openscale.core.bluetooth.libs.S400ChannelDirection
import com.health.openscale.core.bluetooth.libs.S400ChannelEvent
import com.health.openscale.core.bluetooth.libs.S400ChannelFrame
import com.health.openscale.core.bluetooth.libs.S400ChannelReassembler
import com.health.openscale.core.bluetooth.libs.S400SpecCommands
import com.health.openscale.core.bluetooth.libs.S400SpecProtocol
import com.health.openscale.core.bluetooth.libs.S400StandardAuth
import com.health.openscale.core.data.MeasurementType
import kotlinx.coroutines.CoroutineScope
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID
import kotlin.coroutines.EmptyCoroutineContext

/**
 * Scripted, handler-level tests for [MiScaleS400Handler]'s GATT spec channel.
 *
 * Everything here is synthetic: the token is a fixed placeholder, the randoms and the account
 * identifiers are invented constants, and the 32-field CSV carries made-up numbers. No device
 * token, session key, real Xiaomi account id or captured health value appears in this file.
 *
 * The session driver replays the frames the vendor's own channel layer emits, so the
 * handshake, the F0 bootstrap, the 6.6 account switch, event-07 dispatch, status gating, the
 * identity publish gate and the MTU bound are all exercised through
 * `onConnected`/`onNotification` rather than by calling into private state.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MiScaleS400HandlerTest {

    private val miotService = uuid16(0xFE95)
    private val loginCharacteristic = uuid16(0x0010)
    private val authCharacteristic = uuid16(0x0019)
    private val specNotifyCharacteristic = uuid16(0x001B)
    private val specWriteCharacteristic = uuid16(0x001A)

    /** Settings keys the handler reads (see the handler's companion object). */
    private val tokenKey = "s400_gatt_token"
    private val miidKey = "s400_account_miid"
    private val duidKey = "s400_account_duid"
    private val userTypeKey = "s400_account_user_type"
    private val mappedUserKey = "s400_account_app_user_id"

    /** 24 hex characters, i.e. a 12-byte synthetic token — not a credential. */
    private val tokenHex = "00112233445566778899aabb"

    private val token: ByteArray = hex(tokenHex)
    private val appUser = ScaleUser(id = 7, userName = "Session User", bodyHeight = 185f)
    private val otherUser = ScaleUser(id = 9, userName = "Other User")

    private val devRandom = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")

    /** Invented account identity: miid is a 10-digit number, duid 2, user type 1. */
    private val testMiid = "1234567890"
    private val testDuid = 2
    private val testUserType = 1

    // ---- harness --------------------------------------------------------------

    private data class Write(
        val service: UUID,
        val characteristic: UUID,
        val payload: ByteArray,
        val withResponse: Boolean,
    )

    private class RecordingTransport(private val mtu: Int? = null) : ScaleDeviceHandler.Transport {
        val writes = mutableListOf<Write>()
        var disconnected = false

        override fun setNotifyOn(service: UUID, characteristic: UUID) = Unit
        override fun write(service: UUID, characteristic: UUID, payload: ByteArray, withResponse: Boolean) {
            writes += Write(service, characteristic, payload.copyOf(), withResponse)
        }

        override fun read(service: UUID, characteristic: UUID) = Unit
        override fun disconnect() {
            disconnected = true
        }

        override fun getPeripheral() = null
        override fun hasCharacteristic(service: UUID, characteristic: UUID) = true
        override fun negotiatedMtu(): Int? = mtu
    }

    private class RecordingCallbacks : ScaleDeviceHandler.Callbacks {
        val published = mutableListOf<ScaleMeasurement>()
        var warned = 0

        override fun onPublish(measurement: ScaleMeasurement) {
            published += measurement
        }

        override fun onWarn(resId: Int, vararg args: Any) {
            warned++
        }

        override fun resolveString(resId: Int, vararg args: Any) = "res:$resId"
    }

    private class MemorySettings(val values: MutableMap<String, String>) :
        ScaleDeviceHandler.DriverSettings {
        override fun getInt(key: String, default: Int): Int = default
        override fun putInt(key: String, value: Int) = Unit
        override fun getString(key: String, default: String?): String? = values[key] ?: default
        override fun putString(key: String, value: String) {
            values[key] = value
        }

        override fun remove(key: String) {
            values.remove(key)
        }
    }

    /** Mutable provider so a test can switch the app's current user mid-session. */
    private class SwitchableProvider(var current: ScaleUser) : ScaleDeviceHandler.DataProvider {
        override fun currentUser(): ScaleUser = current
        override fun usersForDevice(): List<ScaleUser> = listOf(current)
        override fun lastMeasurementFor(userId: Int): ScaleMeasurement? = null
    }

    private class Setup(
        val handler: MiScaleS400Handler,
        val transport: RecordingTransport,
        val callbacks: RecordingCallbacks,
        val provider: SwitchableProvider,
        val settings: MemorySettings,
    ) {
        /** Device→app AES counter; every inbound frame consumes one. */
        var rxCounter = 0
    }

    /**
     * @param token GATT token, or `null` to leave it unset.
     * @param identity `true` to configure the synthetic mapping for [appUser], `false` to leave
     *   every identity key empty.
     * @param mappedUser openScale user id overriding the mapping's app-user association.
     * @param user the openScale user the link is opened for (height/sex feed the standard weight).
     */
    private fun setup(
        mtu: Int? = null,
        token: String? = tokenHex,
        identity: Boolean = true,
        mappedUser: Int = appUser.id,
        miid: String = testMiid,
        duid: Int = testDuid,
        userType: Int = testUserType,
        user: ScaleUser = appUser,
    ): Setup {
        val handler = MiScaleS400Handler()
        val transport = RecordingTransport(mtu)
        val callbacks = RecordingCallbacks()
        val provider = SwitchableProvider(user)
        val values = mutableMapOf<String, String>()
        if (token != null) values[tokenKey] = token
        if (identity) {
            values[miidKey] = miid
            values[duidKey] = duid.toString()
            values[userTypeKey] = userType.toString()
            values[mappedUserKey] = mappedUser.toString()
        }
        val settings = MemorySettings(values)
        handler.attach(transport, callbacks, settings, provider, CoroutineScope(EmptyCoroutineContext))
        return Setup(handler, transport, callbacks, provider, settings)
    }

    // ---- synthetic spec payloads ----------------------------------------------

    /**
     * A 32-field result CSV matching the vendor's `event.8.2` field order. Values are invented;
     * only their ranges matter to the parser. The first three fields are the device-echoed
     * identity, which must match whatever the handler switched the scale to.
     */
    private fun syntheticCsv(
        status: Int,
        miid: String = testMiid,
        duid: Int = testDuid,
        userType: Int = testUserType,
        time: Long = 1700000000L,
        slp: String = "715",
        impedanceHigh: String = "512",
        impedanceLow: String = "498",
    ): String = listOf(
        miid,         // 0  miid
        "$duid",      // 1  device user id (duid / accountCode)
        "$userType",  // 2  user type
        "812",        // 3  weight, 0.1 kg
        "68",         // 4  heart rate
        "$status",    // 5  status
        "$time",      // 6  timestamp
        "215",        // 7  body fat %
        "560",        // 8  soft lean mass
        "592",        // 9  body water %
        "31",         // 10 bone mass
        "5",          // 11 visceral fat level
        "171",        // 12 protein %
        "340",        // 13 skeletal muscle mass
        "248",        // 14 bmi
        "1", "1", "1", "1", "1", // 15..19
        "1650",       // 20 bmr
        "1",          // 21 body type
        "34",         // 22 metabolic age
        "1", slp, "1", "1", // 23..26 (24 = slp, the muscle % Xiaomi shows)
        "640",        // 27 fat free mass
        "500",        // 28 body water mass
        "120",        // 29 protein mass
        impedanceHigh, // 30 impedance high
        impedanceLow,  // 31 impedance low
    ).joinToString(",")

    /** Build the decrypted MIoT envelope for one event: `07 siid eiid 00 01 02 00 81 a0 csv`. */
    private fun specBody(siid: Int, eiid: Int, csv: String): ByteArray {
        val prefix = byteArrayOf(
            0x07, siid.toByte(), eiid.toByte(),
            0x00, 0x01, 0x02, 0x00, 0x81.toByte(), 0xa0.toByte(),
        )
        return prefix + csv.toByteArray(Charsets.US_ASCII)
    }

    private fun specPlaintext(siid: Int, eiid: Int, status: Int, csv: String = syntheticCsv(status)): ByteArray =
        S400SpecProtocol.wrap(1, specBody(siid, eiid, csv))

    /**
     * Encrypt a device→app frame.
     *
     * [S400StandardAuth.encryptFrame] always uses the *app* direction key/prefix, so the
     * mirror image of the session key is used here: copying the RX half over the TX half
     * makes the result exactly what the handler's RX path expects to decrypt.
     */
    private fun deviceEncrypt(sessionKey: ByteArray, counter: Int, plaintext: ByteArray): ByteArray {
        val mirrored = sessionKey.copyOf()
        System.arraycopy(sessionKey, 0, mirrored, 16, 16)  // TX key := RX key
        System.arraycopy(sessionKey, 32, mirrored, 36, 4)  // TX nonce prefix := RX prefix
        return S400StandardAuth.encryptFrame(mirrored, plaintext, counter)
    }

    /** Decrypt an app→device frame: the mirror of [deviceEncrypt]. */
    private fun appDecrypt(sessionKey: ByteArray, frame: ByteArray): ByteArray? {
        val mirrored = sessionKey.copyOf()
        System.arraycopy(sessionKey, 16, mirrored, 0, 16)   // RX key := TX key
        System.arraycopy(sessionKey, 36, mirrored, 32, 4)   // RX nonce prefix := TX prefix
        return S400StandardAuth.decryptFrame(mirrored, frame)
    }

    // ---- session driver -------------------------------------------------------

    private fun Setup.lastWriteOn(characteristic: UUID): Write =
        transport.writes.last { it.characteristic == characteristic }

    /** Feed one inbound characteristic value, as the adapter would on a notification. */
    private fun Setup.notify(characteristic: UUID, value: ByteArray) {
        handler.handleNotification(characteristic, value)
    }

    private fun Setup.feedAckContinue() {
        notify(authCharacteristic, S400ChannelCodec.ack(S400ChannelCodec.ACK_STATUS_CONTINUE))
    }

    /** Flow-control ack on the spec write characteristic (device grants/completes a transfer). */
    private fun Setup.specAck(status: Int) {
        notify(specWriteCharacteristic, S400ChannelCodec.ack(status))
    }

    /** Deliver one decrypted device→app spec message as a single frame. */
    private fun Setup.deliverSpec(sessionKey: ByteArray, plaintext: ByteArray) {
        val encrypted = deviceEncrypt(sessionKey, rxCounter, plaintext)
        rxCounter += 1
        notify(specNotifyCharacteristic, S400ChannelCodec.single(0, encrypted))
    }

    /**
     * Replays the vendor handshake through the login result and returns the session key.
     * The F0 bootstrap has been written (FRAGMENT_START only); its transport exchange and the
     * echoed reply are left to the caller so ordering can be tested explicitly.
     */
    private fun Setup.driveToLogin(): ByteArray {
        handler.handleConnected(provider.current)

        // Two *distinct* management frames start StandardAuth.
        notify(authCharacteristic, S400ChannelCodec.management(0, hex("0102")))
        notify(authCharacteristic, S400ChannelCodec.management(0, hex("0304")))

        // The handler now grants the app random as a fragmented message.
        feedAckContinue()
        val randomFrame = lastWriteOn(authCharacteristic).payload
        val appRandom = (S400ChannelCodec.decode(randomFrame) as S400ChannelFrame.Data).payload
        assertThat(appRandom).hasLength(16)

        val sessionKey = S400StandardAuth.deriveSessionKey(token, appRandom, devRandom)

        notify(authCharacteristic, S400ChannelCodec.single(S400StandardAuth.OPCODE_DEV_RANDOM, devRandom))
        val deviceConfirm = S400StandardAuth.deviceConfirmation(sessionKey, appRandom, devRandom)
        notify(authCharacteristic, S400ChannelCodec.single(S400StandardAuth.OPCODE_DEV_CONFIRM, deviceConfirm))
        feedAckContinue()

        // The login characteristic answers the app confirmation with `21 00 00 00`, and the
        // handler writes the F0 bootstrap.
        notify(loginCharacteristic, byteArrayOf(0x21, 0x00, 0x00, 0x00))
        return sessionKey
    }

    /** Finish the bootstrap's fragmented transfer: grant, then completion. */
    private fun Setup.completeBootstrapTransport() {
        specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)
        specAck(S400ChannelCodec.ACK_STATUS_COMPLETE)
    }

    /** The device echoes the F0 command verbatim as a decrypted spec message. */
    private fun Setup.deliverBootstrapEcho(sessionKey: ByteArray) {
        deliverSpec(sessionKey, S400SpecProtocol.bootstrap(0))
    }

    /** Finish the 6.6 switch's fragmented transfer. */
    private fun Setup.completeSwitchTransport() {
        specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)
        specAck(S400ChannelCodec.ACK_STATUS_COMPLETE)
    }

    /** Full happy path: bootstrap echoed + transferred, switch transferred, acknowledged. */
    private fun Setup.driveToReady(): ByteArray {
        val key = driveToLogin()
        completeBootstrapTransport()
        deliverBootstrapEcho(key)
        completeSwitchTransport()
        deliverSwitchReply(key, code = 0)
        return key
    }

    /**
     * Deliver the op-06 reply to the 6.6 action.
     *
     * Body layout is `06 siid aiid code` after the 4-byte envelope. [code] `= null` omits the
     * status byte, which must be treated as a refusal, not as success.
     */
    private fun Setup.deliverSwitchReply(
        sessionKey: ByteArray,
        code: Int?,
        sequence: Int = 1,
        siid: Int = S400SpecCommands.SIID_USER,
        aiid: Int = S400SpecCommands.AIID_USER_SWITCH,
    ) {
        val body = if (code == null) {
            byteArrayOf(0x06)
        } else if (siid != 6 || aiid != 6) {
            // A longer device-info reply is not a bare action status.
            byteArrayOf(0x06, 0, 0, 5)
        } else {
            byteArrayOf(0x06, code.toByte(), (code ushr 8).toByte())
        }
        deliverSpec(sessionKey, S400SpecProtocol.wrap(sequence, body))
    }

    private fun Setup.deliverResult(
        sessionKey: ByteArray,
        siid: Int,
        eiid: Int,
        status: Int,
        csv: String = syntheticCsv(status),
    ) {
        deliverSpec(sessionKey, specPlaintext(siid, eiid, status, csv))
    }

    /**
     * Every complete app→device spec message written on the spec characteristic, decrypted.
     * Used to assert on the bootstrap and switch frames that actually reached the transport.
     *
     * @param from index into the write log to start from, for sessions that follow a reconnect.
     */
    private fun Setup.sentSpecPlaintexts(sessionKey: ByteArray, from: Int = 0): List<ByteArray> {
        val reasm = S400ChannelReassembler()
        val out = mutableListOf<ByteArray>()
        for (write in transport.writes.drop(from).filter { it.characteristic == specWriteCharacteristic }) {
            val frame = S400ChannelCodec.decode(write.payload) ?: continue
            for (event in reasm.accept(S400ChannelDirection.APP_TO_DEVICE, 0x001A, frame)) {
                if (event is S400ChannelEvent.Message) {
                    appDecrypt(sessionKey, event.payload)?.let { out += it }
                }
            }
        }
        return out
    }

    /** `true` when a decrypted plaintext is a 6.6 switchUser action. */
    private fun isSwitchUser(plaintext: ByteArray): Boolean =
        plaintext.size == 30 &&
            (plaintext[4].toInt() and 0xff) == S400SpecCommands.OP_ACTION &&
            (plaintext[5].toInt() and 0xff) == S400SpecCommands.SIID_USER &&
            (plaintext[6].toInt() and 0xff) == S400SpecCommands.AIID_USER_SWITCH

    private fun Setup.sentSwitchFrames(sessionKey: ByteArray): List<ByteArray> =
        sentSpecPlaintexts(sessionKey).filter(::isSwitchUser)

    /**
     * Spec-write FRAGMENT_START frames in order.
     *
     * A fragmented command is only fully decryptable after the device grants continuation, so
     * the *start* of an outbound message is the observable signal that the handler began sending
     * it. Only the bootstrap (1 fragment) and the 6.6 switch (2 fragments) are ever written here.
     */
    private fun Setup.specFragmentStarts(): List<S400ChannelFrame.FragmentStart> =
        transport.writes
            .filter { it.characteristic == specWriteCharacteristic }
            .mapNotNull { S400ChannelCodec.decode(it.payload) }
            .filterIsInstance<S400ChannelFrame.FragmentStart>()

    // ---- event 07 validation --------------------------------------------------

    @Test
    fun `event identity accepts the captured event07 result layout`() {
        val identity = MiScaleS400Handler.specEventIdentity(specPlaintext(8, 2, 0))

        assertThat(identity).isNotNull()
        assertThat(identity!!.first).isEqualTo(0x07)
        assertThat(identity.second).isEqualTo(0x08)
        assertThat(identity.third).isEqualTo(0x02)
        assertThat(MiScaleS400Handler.isFinalResultEvent(specPlaintext(8, 2, 0))).isTrue()
    }

    @Test
    fun `live weight event 8_1 is not a final result`() {
        assertThat(MiScaleS400Handler.isFinalResultEvent(specPlaintext(8, 1, 0))).isFalse()
    }

    @Test
    fun `non event spec reply has no event identity`() {
        // The device-info reply uses type 0x06, not an event notification.
        val reply = S400SpecProtocol.wrap(3, byteArrayOf(0x06, 0x00, 0x00))

        assertThat(MiScaleS400Handler.specEventIdentity(reply)).isNull()
        assertThat(MiScaleS400Handler.isFinalResultEvent(reply)).isFalse()
    }

    @Test
    fun `truncated body has no event identity`() {
        assertThat(MiScaleS400Handler.specEventIdentity(byteArrayOf(0x07, 0x08))).isNull()
        assertThat(MiScaleS400Handler.specEventIdentity(ByteArray(0))).isNull()
    }

    @Test
    fun `unknown service event is not a final result`() {
        assertThat(MiScaleS400Handler.isFinalResultEvent(specPlaintext(10, 1, 0))).isFalse()
    }

    // ---- status gating --------------------------------------------------------

    @Test
    fun `status zero is publishable`() {
        assertThat(MiScaleS400Handler.isPublishableStatus(0)).isTrue()
    }

    @Test
    fun `impedance failure still carries a valid weight`() {
        // Status 1 = impedance/HR measurement failed; the weight is still real, and the
        // vendor's handler falls through to its normal save path.
        assertThat(MiScaleS400Handler.isPublishableStatus(1)).isTrue()
    }

    @Test
    fun `ambiguous user match keeps the vendor fallback`() {
        assertThat(MiScaleS400Handler.isPublishableStatus(4)).isTrue()
    }

    @Test
    fun `unmatched user statuses are not attributable`() {
        assertThat(MiScaleS400Handler.isPublishableStatus(2)).isFalse()
        assertThat(MiScaleS400Handler.isPublishableStatus(3)).isFalse()
    }

    @Test
    fun `small item lock and overweight exit are dropped`() {
        assertThat(MiScaleS400Handler.isPublishableStatus(6)).isFalse()
        assertThat(MiScaleS400Handler.isPublishableStatus(7)).isFalse()
    }

    @Test
    fun `unknown status keeps the vendor fallback`() {
        assertThat(MiScaleS400Handler.isPublishableStatus(5)).isTrue()
        assertThat(MiScaleS400Handler.isPublishableStatus(99)).isTrue()
    }

    // ---- identity parsing -----------------------------------------------------

    @Test
    fun `complete identity parses`() {
        val identity = MiScaleS400Handler.parseIdentity("1234567890", "2", "1", "7")

        assertThat(identity).isNotNull()
        assertThat(identity!!.miid).isEqualTo(1234567890L)
        assertThat(identity.duid).isEqualTo(2)
        assertThat(identity.userType).isEqualTo(1)
        assertThat(identity.appUserId).isEqualTo(7)
    }

    @Test
    fun `incomplete or out of range identity is rejected`() {
        // Any missing field must fail closed rather than fill a default.
        assertThat(MiScaleS400Handler.parseIdentity(null, "2", "1", "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("1234567890", null, "1", "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("1234567890", "2", null, "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("1234567890", "2", "1", null)).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("", "2", "1", "7")).isNull()
        // Out of range / non-numeric values.
        assertThat(MiScaleS400Handler.parseIdentity("0", "2", "1", "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("abc", "2", "1", "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("1234567890", "256", "1", "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("1234567890", "2", "4", "7")).isNull()
        assertThat(MiScaleS400Handler.parseIdentity("1234567890", "2", "1", "0")).isNull()
    }

    @Test
    fun `account id is masked for display`() {
        assertThat(MiScaleS400Handler.maskAccountId("1234567890")).isEqualTo("••••7890")
        assertThat(MiScaleS400Handler.maskAccountId("1234")).isEqualTo("••••")
        assertThat(MiScaleS400Handler.maskAccountId("")).isEqualTo("••••")
    }

    @Test
    fun `identity match requires miid duid and user type to agree`() {
        val identity = MiScaleS400Handler.parseIdentity("1234567890", "2", "1", "7")!!
        val matching = S400SpecMeasurementTestAccess.parse(syntheticCsv(0))!!
        val otherMiid = S400SpecMeasurementTestAccess.parse(syntheticCsv(0, miid = "9999999999"))!!
        val otherDuid = S400SpecMeasurementTestAccess.parse(syntheticCsv(0, duid = 3))!!
        val otherType = S400SpecMeasurementTestAccess.parse(syntheticCsv(0, userType = 0))!!

        assertThat(MiScaleS400Handler.identityMatches(identity, matching)).isTrue()
        assertThat(MiScaleS400Handler.identityMatches(identity, otherMiid)).isFalse()
        assertThat(MiScaleS400Handler.identityMatches(identity, otherDuid)).isFalse()
        assertThat(MiScaleS400Handler.identityMatches(identity, otherType)).isFalse()
    }

    // ---- management handshake -------------------------------------------------

    /** The app-random FRAGMENT_START the handler emits when StandardAuth begins. */
    private fun Setup.appRandomStart(): S400ChannelFrame.FragmentStart? =
        transport.writes
            .mapNotNull { S400ChannelCodec.decode(it.payload) }
            .filterIsInstance<S400ChannelFrame.FragmentStart>()
            .lastOrNull { it.packageType == S400StandardAuth.OPCODE_APP_RANDOM }

    private fun Setup.authGrantWrites(): List<Write> =
        transport.writes.filter { it.payload.contentEquals(byteArrayOf(0x24, 0x00, 0x00, 0x00)) }

    @Test
    fun `duplicate management frames do not start standard auth`() {
        val s = setup()
        s.handler.handleConnected(appUser)

        // The same management frame four times: a retransmit must not count twice.
        repeat(4) { s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0102"))) }

        assertThat(s.appRandomStart()).isNull()
        assertThat(s.authGrantWrites()).isEmpty()
        // Each frame is still acknowledged, so the device is never left waiting.
        assertThat(s.transport.writes).hasSize(5) // 0xA4 kickoff + 4 acks
    }

    @Test
    fun `two distinct management frames start standard auth`() {
        val s = setup()
        s.handler.handleConnected(appUser)

        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0102")))
        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0304")))

        assertThat(s.authGrantWrites()).hasSize(1)
        assertThat(s.authGrantWrites().single().characteristic).isEqualTo(loginCharacteristic)

        val started = s.appRandomStart()
        assertThat(started).isNotNull()
        assertThat(started!!.frameCount).isEqualTo(1)
    }

    @Test
    fun `a third distinct management frame does not restart the handshake`() {
        val s = setup()
        s.handler.handleConnected(appUser)

        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0102")))
        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0304")))
        val afterStart = s.transport.writes.size

        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0506")))

        // Acked, but no second grant and no second app-random start.
        assertThat(s.transport.writes.size).isEqualTo(afterStart + 1)
        assertThat(s.authGrantWrites()).hasSize(1)
        assertThat(
            s.transport.writes.count { write ->
                S400ChannelCodec.decode(write.payload) is S400ChannelFrame.FragmentStart
            }
        ).isEqualTo(1)
    }

    @Test
    fun `management traffic is acknowledged on its own channel`() {
        // Management tracking must stay distinct from the spec stream: acks go back to the
        // characteristic the frame arrived on, never onto the encrypted spec channel.
        val s = setup()
        s.handler.handleConnected(appUser)

        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0102")))
        s.notify(authCharacteristic, S400ChannelCodec.management(0, hex("0304")))

        val acks = s.transport.writes.filter { write ->
            S400ChannelCodec.decode(write.payload) is S400ChannelFrame.ManagementAck
        }
        assertThat(acks).hasSize(2)
        assertThat(acks.map { it.characteristic })
            .containsExactly(authCharacteristic, authCharacteristic)
        assertThat(acks.map { it.service }).containsExactly(miotService, miotService)
        assertThat(acks.none { it.characteristic == specWriteCharacteristic }).isTrue()
    }

    // ---- end-to-end publish ---------------------------------------------------

    @Test
    fun `authenticated final result publishes a measurement`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).hasSize(1)
        val measurement = s.callbacks.published.single()
        assertThat(measurement.userId).isEqualTo(appUser.id)
        assertThat(measurement[MeasurementType.WEIGHT]!!.value).isWithin(1e-3f).of(81.2f)
        assertThat(measurement[MeasurementType.BODY_FAT]!!.value).isWithin(1e-3f).of(21.5f)
        assertThat(measurement[MeasurementType.HEART_RATE]!!.value).isEqualTo(68)
    }

    @Test
    fun `muscle percentage follows the vendor slp field`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        // slp = 71.5 %, not smm/weight (34.0 kg of 81.2 kg = 41.9 %).
        assertThat(s.callbacks.published.single()[MeasurementType.MUSCLE]!!.value).isWithin(1e-3f).of(71.5f)
    }

    @Test
    fun `muscle percentage falls back to skeletal muscle when slp is absent`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0, csv = syntheticCsv(0, slp = "0"))

        assertThat(s.callbacks.published.single()[MeasurementType.MUSCLE]!!.value)
            .isWithin(0.01f).of(340f / 812f * 100f)
    }

    @Test
    fun `standard weight is derived from the profile and published with a full result`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        // (185 - 80) * 0.7 = 73.5 kg for the male test profile.
        assertThat(s.callbacks.published.single()[MiScaleS400Handler.IDEAL_WEIGHT]!!.value)
            .isWithin(1e-3f).of(73.5f)
    }

    @Test
    fun `standard weight is omitted when the profile has no usable height`() {
        val s = setup(user = appUser.copy(bodyHeight = -1f))
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        val m = s.callbacks.published.single()
        assertThat(MiScaleS400Handler.IDEAL_WEIGHT in m).isFalse()
        assertThat(m[MeasurementType.BODY_FAT]).isNotNull()
    }

    @Test
    fun `result without impedance publishes weight and pulse only`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0,
            csv = syntheticCsv(0, impedanceHigh = "0", impedanceLow = "0"))

        val m = s.callbacks.published.single()
        assertThat(m[MeasurementType.WEIGHT]!!.value).isWithin(1e-3f).of(81.2f)
        assertThat(m[MeasurementType.HEART_RATE]!!.value).isEqualTo(68)
        listOf(
            MeasurementType.BODY_FAT, MeasurementType.WATER, MeasurementType.MUSCLE,
            MeasurementType.BONE, MeasurementType.LBM, MeasurementType.VISCERAL_FAT,
            MeasurementType.BMR, MeasurementType.PROTEIN,
            MeasurementType.IMPEDANCE, MeasurementType.IMPEDANCE_LOW,
        ).forEach { assertThat(it in m).isFalse() }
        assertThat(MiScaleS400Handler.METABOLIC_AGE in m).isFalse()
        assertThat(MiScaleS400Handler.IDEAL_WEIGHT in m).isFalse()
    }

    @Test
    fun `one missing impedance band counts as no composition`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0,
            csv = syntheticCsv(0, impedanceHigh = "512", impedanceLow = "0"))

        assertThat(MeasurementType.BODY_FAT in s.callbacks.published.single()).isFalse()
    }

    @Test
    fun `standard weight matches the vendor formula for both sexes`() {
        assertThat(MiScaleS400Handler.standardWeightKg(185f, male = true)).isEqualTo(73.5f)
        assertThat(MiScaleS400Handler.standardWeightKg(165f, male = false)).isEqualTo(57.0f)
        assertThat(MiScaleS400Handler.standardWeightKg(-1f, male = true)).isNull()
        assertThat(MiScaleS400Handler.standardWeightKg(40f, male = false)).isNull()
        assertThat(MiScaleS400Handler.standardWeightKg(Float.NaN, male = true)).isNull()
    }

    @Test
    fun `result is credited to the user the link was opened for`() {
        val s = setup()
        val key = s.driveToReady()

        // The app switches user while the link is still open; the result belongs to the
        // session's user, not whoever happens to be selected at notification time.
        s.provider.current = otherUser

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).hasSize(1)
        assertThat(s.callbacks.published.single().userId).isEqualTo(appUser.id)
    }

    @Test
    fun `unmatched user result is not published`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 2)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `non compliant user info result is not published`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 3)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `overweight exit result is not published`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 2, status = 7)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `live weight event never publishes`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverResult(key, siid = 8, eiid = 1, status = 0)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `non event reply after login never publishes`() {
        val s = setup()
        val key = s.driveToReady()

        val reply = S400SpecProtocol.wrap(5, byteArrayOf(0x06, 0x00, 0x00))
        s.deliverSpec(key, reply)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `repeated identical result is published once`() {
        val s = setup()
        val key = s.driveToReady()

        // Distinct receive counters, so both frames decrypt and the second is suppressed
        // by the result-timestamp guard rather than by replay protection.
        s.deliverResult(key, siid = 8, eiid = 2, status = 0)
        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).hasSize(1)
    }

    // ---- 6.6 switchUser -------------------------------------------------------

    @Test
    fun `configured identity is switched with the exact 6_6 frame`() {
        val s = setup()
        val key = s.driveToLogin()

        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)

        // The switch is fragmented: grant continuation so its payload frames are sent, then the
        // decrypted command can be compared byte-for-byte with the verified encoder output.
        assertThat(s.specFragmentStarts()).hasSize(2) // bootstrap + switch
        s.specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)

        val frames = s.sentSwitchFrames(key)
        assertThat(frames).hasSize(1)
        // Byte-for-byte equal to the verified encoder output for the configured identity:
        // sequence 1, miid 1234567890, duid 2, user type 1.
        assertThat(frames.single()).isEqualTo(
            S400SpecCommands.switchUserFrame(1, 1234567890L, testDuid, testUserType)
        )
    }

    @Test
    fun `switch is not sent before the bootstrap echo arrives`() {
        val s = setup()
        val key = s.driveToLogin()

        s.completeBootstrapTransport()
        // Only the bootstrap has been started; nothing else may be queued behind it.
        assertThat(s.specFragmentStarts()).hasSize(1)

        s.deliverBootstrapEcho(key)
        assertThat(s.specFragmentStarts()).hasSize(2)
    }

    @Test
    fun `switch is not sent before the bootstrap transport completes`() {
        val s = setup()
        val key = s.driveToLogin()

        // Echo first: the plaintext reply alone must not free the spec write slot, because the
        // fragmented bootstrap is still mid-transfer.
        s.deliverBootstrapEcho(key)
        assertThat(s.specFragmentStarts()).hasSize(1)

        s.specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)
        assertThat(s.specFragmentStarts()).hasSize(1)

        s.specAck(S400ChannelCodec.ACK_STATUS_COMPLETE)
        assertThat(s.specFragmentStarts()).hasSize(2)
    }

    @Test
    fun `switch is sent exactly once even if the echo is repeated`() {
        val s = setup()
        val key = s.driveToReady()

        s.deliverBootstrapEcho(key)

        assertThat(s.sentSwitchFrames(key)).hasSize(1)
    }

    @Test
    fun `envelope sequences increment independently of the aes counters`() {
        val s = setup()
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)
        // Grant continuation so the switch's payload frames are actually written; only then is
        // its plaintext decryptable and the envelope sequence readable.
        s.specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)

        val sent = s.sentSpecPlaintexts(key)
        val bootstrap = sent.first()
        val switch = sent.first(::isSwitchUser)

        // Envelope sequence: bootstrap 0, switch 1. The AES counters are a separate sequence
        // owned by S400StandardAuthSession and are never reused for the envelope.
        assertThat(bootstrap[2].toInt() and 0xff).isEqualTo(0)
        assertThat(bootstrap[3].toInt() and 0xff).isEqualTo(0)
        assertThat(switch[2].toInt() and 0xff).isEqualTo(1)
        assertThat(switch[3].toInt() and 0xff).isEqualTo(0)
    }

    @Test
    fun `missing identity sends no switch and saves nothing`() {
        val s = setup(identity = false)
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)

        // The handshake still completes so the misconfiguration is visible...
        assertThat(s.sentSwitchFrames(key)).isEmpty()
        assertThat(s.callbacks.warned).isGreaterThan(0)

        // ...but a perfectly well-formed result is not stored.
        s.deliverResult(key, siid = 8, eiid = 2, status = 0)
        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `identity mapped to another app user is never sent`() {
        val s = setup(mappedUser = otherUser.id)
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)

        // The link was opened for appUser, but the configured identity belongs to otherUser:
        // another account's identifiers must never be put on the wire.
        assertThat(s.sentSwitchFrames(key)).isEmpty()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)
        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `switch reply with non zero status blocks the result`() {
        val s = setup()
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)
        s.completeSwitchTransport()
        s.deliverSwitchReply(key, code = 1)

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `switch reply without a status byte blocks the result`() {
        val s = setup()
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)
        s.completeSwitchTransport()
        // Truncated op-06 reply: no result code at all must never be read as success.
        s.deliverSwitchReply(key, code = null)

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `switch reply with a foreign sequence or action does not resolve the switch`() {
        val s = setup()
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)
        s.completeSwitchTransport()

        // A stale sequence and a 13.1 device-info answer must neither resolve nor pre-empt the
        // real 6.6 reply that follows them.
        s.deliverSwitchReply(key, code = 0, sequence = 9)
        s.deliverSwitchReply(key, code = 0, sequence = 1, siid = 13, aiid = 1)
        s.deliverSwitchReply(key, code = 1)

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `identity match alone publishes when the device sends no reply`() {
        // The echoed identity in the result is the authoritative evidence that the slot changed;
        // an op-06 acknowledgement is a fast path, not a requirement. A device that never answers
        // 6.6 must not lose a perfectly attributed measurement.
        val s = setup()
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)
        s.completeSwitchTransport()

        s.deliverResult(key, siid = 8, eiid = 2, status = 0)

        assertThat(s.callbacks.published).hasSize(1)
    }

    @Test
    fun `result from a different account is dropped`() {
        val s = setup()
        val key = s.driveToReady()

        // The device still reports the previous occupant of the slot: same weight, other ids.
        s.deliverResult(key, siid = 8, eiid = 2, status = 0,
            csv = syntheticCsv(0, miid = "9999999999", duid = 5, userType = 0))

        assertThat(s.callbacks.published).isEmpty()
    }

    @Test
    fun `result is dropped and nothing is persisted when no mapping is configured`() {
        val s = setup(identity = false)
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)

        // Plausible-looking ids in the packet must never be adopted or stored.
        s.deliverResult(key, siid = 8, eiid = 2, status = 0,
            csv = syntheticCsv(0, miid = "5555555555", duid = 4, userType = 1))

        assertThat(s.callbacks.published).isEmpty()
        assertThat(s.settings.values.keys).containsNoneOf(miidKey, duidKey, userTypeKey, mappedUserKey)
        assertThat(s.settings.values.values.none { it.contains("5555555555") }).isTrue()
    }

    @Test
    fun `switch survives a device-initiated fragment flow`() {
        // The switch is itself fragmented: the handler must emit its data frames only after the
        // device grants continuation, and its completion must not re-send the command.
        val s = setup()
        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)

        val beforeGrant = s.specFragmentStarts()
        assertThat(beforeGrant).hasSize(2)   // bootstrap + switch FRAGMENT_START only
        assertThat(s.sentSwitchFrames(key)).isEmpty()

        s.specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)
        assertThat(s.sentSwitchFrames(key)).hasSize(1)

        s.specAck(S400ChannelCodec.ACK_STATUS_COMPLETE)
        assertThat(s.sentSwitchFrames(key)).hasSize(1)
        assertThat(s.specFragmentStarts()).hasSize(2)
    }

    // ---- MTU plumbing ---------------------------------------------------------

    @Test
    fun `known mtu bounds inbound characteristic values`() {
        // At ATT MTU 23 no notification can be larger than 20 bytes: a 34-byte
        // management frame cannot be a real one and must be discarded.
        val s = setup(mtu = ScaleDeviceHandler.DEFAULT_ATT_MTU)
        s.handler.handleConnected(appUser)

        s.notify(authCharacteristic, S400ChannelCodec.management(0, ByteArray(30)))

        assertThat(s.transport.writes).hasSize(1) // still just the 0xA4 kickoff
    }

    @Test
    fun `unknown mtu keeps the protocol maximum`() {
        // Transports without a readback must not silently fall back to MTU 23, which
        // would reject the S400's legitimate 244-byte management notification.
        val s = setup(mtu = null)
        s.handler.handleConnected(appUser)

        s.notify(authCharacteristic, S400ChannelCodec.management(0, ByteArray(30)))

        val ack = S400ChannelCodec.decode(s.transport.writes.last().payload)
        assertThat(ack).isInstanceOf(S400ChannelFrame.ManagementAck::class.java)
    }

    @Test
    fun `mtu bounds are clamped to the s400 maximum`() {
        // ATT MTU 517 would allow a 514-byte value, but the S400 protocol never exceeds
        // 244; a larger value must still be rejected instead of being accepted.
        val s = setup(mtu = 517)
        s.handler.handleConnected(appUser)

        s.notify(authCharacteristic, S400ChannelCodec.management(0, ByteArray(300)))

        assertThat(s.transport.writes).hasSize(1) // still just the 0xA4 kickoff
    }

    // ---- configuration --------------------------------------------------------

    @Test
    fun `missing token disconnects before any write`() {
        val s = setup(token = null)

        s.handler.handleConnected(appUser)

        assertThat(s.transport.writes).isEmpty()
        assertThat(s.transport.disconnected).isTrue()
        assertThat(s.callbacks.warned).isEqualTo(1)
    }

    @Test
    fun `malformed token is rejected`() {
        val s = setup(token = "zz112233445566778899aabb")

        s.handler.handleConnected(appUser)

        assertThat(s.transport.writes).isEmpty()
        assertThat(s.transport.disconnected).isTrue()
    }

    @Test
    fun `a new session restarts envelope numbering and still switches`() {
        val s = setup()
        s.driveToReady()

        val secondSessionStart = s.transport.writes.size
        s.handler.handleDisconnected()

        val key = s.driveToLogin()
        s.completeBootstrapTransport()
        s.deliverBootstrapEcho(key)
        // Grant continuation so both the bootstrap and the switch payload frames are written.
        s.specAck(S400ChannelCodec.ACK_STATUS_CONTINUE)

        val sent = s.sentSpecPlaintexts(key, from = secondSessionStart)
        // A fresh session restarts its envelope numbering at 0 (bootstrap) then 1 (switch),
        // proving the per-session state, including the identity snapshot, was re-initialised.
        assertThat(sent).hasSize(2)
        assertThat(sent[0][2].toInt() and 0xff).isEqualTo(0)
        assertThat(isSwitchUser(sent[1])).isTrue()
        assertThat(sent[1][2].toInt() and 0xff).isEqualTo(1)
    }
}

/** Parser access for identity-match fixtures, without duplicating CSV construction. */
private object S400SpecMeasurementTestAccess {
    fun parse(csv: String) =
        com.health.openscale.core.bluetooth.libs.S400SpecMeasurement.parse(csv.toByteArray(Charsets.US_ASCII))
}
