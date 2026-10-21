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
package com.health.openscale.core.bluetooth.scales

import android.bluetooth.le.ScanResult
import android.os.ParcelUuid
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.health.openscale.R
import com.health.openscale.core.data.MeasurementType
import com.health.openscale.core.data.UnitType
import com.health.openscale.core.data.MeasurementTypeIcon
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.bluetooth.libs.S400Aggregator
import com.health.openscale.core.bluetooth.libs.S400ChannelCodec
import com.health.openscale.core.bluetooth.libs.S400ChannelDirection
import com.health.openscale.core.bluetooth.libs.S400ChannelEvent
import com.health.openscale.core.bluetooth.libs.S400ChannelFrame
import com.health.openscale.core.bluetooth.libs.S400ChannelReassembler
import com.health.openscale.core.bluetooth.libs.S400SpecCommands
import com.health.openscale.core.bluetooth.libs.S400SpecMeasurement
import com.health.openscale.core.bluetooth.libs.S400SpecProtocol
import com.health.openscale.core.bluetooth.libs.S400StandardAuth
import com.health.openscale.core.bluetooth.libs.S400StandardAuthSession
import java.security.SecureRandom
import java.util.UUID
import com.health.openscale.core.bluetooth.libs.S400BodyComposition
import com.health.openscale.core.bluetooth.libs.S400BodyFatV235
import com.health.openscale.core.bluetooth.libs.S400Decryptor
import com.health.openscale.core.bluetooth.libs.S400Inputs
import com.health.openscale.core.data.GenderType
import com.health.openscale.core.service.ScannedDeviceInfo
import java.util.Date
import java.util.Locale
import kotlin.text.isNotEmpty
import kotlin.text.lowercase
import com.health.openscale.core.data.Bpm
import com.health.openscale.core.data.Kcal
import com.health.openscale.core.data.Kg
import com.health.openscale.core.data.Ohm
import com.health.openscale.core.data.Percent

/**
 * Xiaomi Body Composition Scale S400 handler.
 *
 * Based on https://github.com/lswiderski/mi-scale-exporter and
 * https://github.com/lswiderski/MiScaleBodyComposition
 *
 * The S400 broadcasts AES-CCM encrypted advertisement data containing:
 * - Weight
 * - Impedance (for body composition calculation)
 * - Heart rate
 *
 * Unlike older Mi Scales, the S400 requires:
 * - A BLE bind key extracted from Xiaomi Cloud
 * - The scale's MAC address (used in nonce construction)
 *
 * This scale uses broadcast-only mode (no GATT connection) and sends
 * AES-CCM encrypted service data in BLE advertisements.
 */
class MiScaleS400Handler : ScaleDeviceHandler() {

    companion object {
        // Settings keys for S400 configuration
        val METABOLIC_AGE = MeasurementType.deviceInt(
            "metabolic_age", R.string.measurement_type_metabolic_age,
            icon = MeasurementTypeIcon.IC_M_PERSON, color = 0xFF8D6E63.toInt()
        )
        val IDEAL_WEIGHT = MeasurementType.deviceKg(
            "ideal_weight", R.string.measurement_type_ideal_weight,
            icon = MeasurementTypeIcon.IC_WEIGHT, color = 0xFF81C784.toInt()
        )

        private const val SETTINGS_KEY_BIND_KEY = "s400_bind_key"
        private const val SETTINGS_KEY_GATT_TOKEN = "s400_gatt_token"
        private const val SETTINGS_KEY_MAC_ADDRESS = "s400_mac_address"

        /**
         * Account identity the scale must be switched to before it attributes a result to us.
         *
         * These four values are entered by the user and are **never** derived, guessed or
         * auto-learned from a device result: a scale echoes whichever identity it currently
         * has selected, so learning from the first 8.2 packet would permanently bind openScale
         * to whatever account happened to be active on the hardware.
         *
         *  * `miid`     — Xiaomi account ID (`Service.account.ID`), a 64-bit number. Distinct
         *                 from the scale's device id / MAC.
         *  * `duid`     — Xiaomi `accountCode`, the per-account slot the firmware stores
         *                 (uint8, sent as `uid` in 6.6).
         *  * `userType` — firmware user type for that slot (uint8). Verified live: 1 = owner,
         *                 family members are 2 (guest-like profiles added from the scale screen).
         *                 0 has not been observed in real traffic; treat as unknown.
         *  * `appUserId`— the openScale `ScaleUser.id` this identity belongs to. Results are
         *                 only saved for that user, and only that user may trigger the switch.
         */
        private const val SETTINGS_KEY_MIID = "s400_account_miid"
        private const val SETTINGS_KEY_DUID = "s400_account_duid"
        private const val SETTINGS_KEY_USER_TYPE = "s400_account_user_type"
        private const val SETTINGS_KEY_MAPPED_USER_ID = "s400_account_app_user_id"


        /** Highest `userType` the firmware was observed to use; wider values are rejected. */
        private const val MAX_USER_TYPE = 3

        /**
         * Validated, immutable account identity snapshot for one connection.
         *
         * Read once in [onConnected] so a settings edit (or an app-user switch) during the link
         * cannot silently re-point the publish gate mid-session.
         */
        internal data class S400Identity(
            val miid: Long,
            val duid: Int,
            val userType: Int,
            val appUserId: Int,
        )

        /** Parsed MIoT action reply (op `0x06`), carrying only status-relevant fields. */
        internal data class ActionReply(
            val sequence: Int,
            val code: Int,
        )

        /**
         * Validate the four configured identity values.
         *
         * Returns `null` unless every value is present and in range, so a partially filled form
         * can never produce a switch command with an invented placeholder.
         */
        internal fun parseIdentity(
            miid: String?,
            duid: String?,
            userType: String?,
            appUserId: String?,
        ): S400Identity? {
            val miidValue = miid?.trim()?.takeIf { it.isNotEmpty() }?.toLongOrNull() ?: return null
            val duidValue = duid?.trim()?.takeIf { it.isNotEmpty() }?.toIntOrNull() ?: return null
            val typeValue = userType?.trim()?.takeIf { it.isNotEmpty() }?.toIntOrNull() ?: return null
            val userValue = appUserId?.trim()?.takeIf { it.isNotEmpty() }?.toIntOrNull() ?: return null
            if (miidValue <= 0) return null
            if (duidValue !in 1..0xFF) return null
            if (typeValue !in 0..MAX_USER_TYPE) return null
            if (userValue <= 0) return null
            return S400Identity(miidValue, duidValue, typeValue, userValue)
        }

        /**
         * `true` only when the device-echoed identity fields equal the configured snapshot.
         *
         * `duid` in the result is the firmware's `accountCode`, i.e. the `uid` sent in 6.6.
         */
        internal fun identityMatches(identity: S400Identity, result: S400SpecMeasurement): Boolean =
            result.miid == identity.miid &&
                result.deviceUserId == identity.duid &&
                result.userType == identity.userType

        /**
         * Parse a decrypted MIoT action reply body.
         *
         * Captured layout: `LE16(len|0x2000) LE16(sequence) 06 statusLE16`.
         * Exactly seven bytes are required; longer device-info replies and truncated
         * status values are not bare action acknowledgements. Only the outstanding
         * sequence identifies the action: the response does not echo siid/aiid.
         */
        internal fun parseActionReply(plaintext: ByteArray): ActionReply? {
            if (plaintext.size < SPEC_HEADER_LENGTH + 3) return null
            val encodedLength = (plaintext[0].toInt() and 0xff) or
                ((plaintext[1].toInt() and 0x1f) shl 8)
            if (encodedLength != plaintext.size) return null
            if ((plaintext[1].toInt() and 0xe0) != 0x20) return null
            if ((plaintext[SPEC_HEADER_LENGTH].toInt() and 0xff) != SPEC_ACTION_REPLY_TYPE) return null
            val sequence = (plaintext[2].toInt() and 0xff) or ((plaintext[3].toInt() and 0xff) shl 8)
            // Captured action response: op06 + status LE16. It does NOT echo
            // siid/aiid; correlate exclusively with the outstanding request sequence.
            if (plaintext.size != SPEC_HEADER_LENGTH + 3) return null
            val code = (plaintext[5].toInt() and 0xff) or
                ((plaintext[6].toInt() and 0xff) shl 8)
            return ActionReply(sequence, code)
        }

        /**
         * Xiaomi's "Standard Weight" (field `swt`): `(height - 80) * 0.7` for men and
         * `(height - 70) * 0.6` for women, rounded to 0.1 kg. Verified against 46/46 records of a
         * male profile in the vendor cloud. `null` for a height outside 50..250 cm, which would
         * only produce a meaningless number (the profile default is -1).
         */
        internal fun standardWeightKg(heightCm: Float, male: Boolean): Float? {
            if (!heightCm.isFinite() || heightCm !in 50f..250f) return null
            val raw = if (male) (heightCm - 80.0) * 0.7 else (heightCm - 70.0) * 0.6
            return (Math.floor(raw * 10.0 + 0.5 + 0.00001) / 10.0).toFloat().takeIf { it > 0f }
        }

        /** Quantities the S400 reports itself; see [ScaleMeasurement.noCarryOver]. */
        private val S400_MEASURED_KEYS: Set<MeasurementType.Key<*>> = setOf(
            MeasurementType.HEART_RATE, MeasurementType.BODY_FAT, MeasurementType.WATER,
            MeasurementType.MUSCLE, MeasurementType.BONE, MeasurementType.LBM,
            MeasurementType.VISCERAL_FAT, MeasurementType.PROTEIN,
            METABOLIC_AGE, IDEAL_WEIGHT,
        )

        /** Mask an account id for display: only the last four characters remain. */
        internal fun maskAccountId(value: String): String =
            if (value.length <= 4) "••••" else "••••" + value.takeLast(4)

        /**
         * Distinct channel-management frames the vendor's channel manager sends before
         * it starts StandardAuth. Duplicates/retransmits must not advance this count.
         */
        private const val MANAGEMENT_FRAMES_EXPECTED = 2

        /** 4-byte proprietary spec header that precedes every MIoT spec body. */
        private const val SPEC_HEADER_LENGTH = 4

        /** MIoT spec event-notification type byte: the `07` of the captured `07 08 02` prefix. */
        private const val SPEC_EVENT_TYPE = 0x07

        /**
         * MIoT spec action-reply type byte: the device answers an op-5 action with an op-6 frame.
         * Verified against the vendor's own decoder, where `06` frames are the action responses
         * that resolve `doAction()`; the repository's captured bootstrap/dev-info frames are the
         * same shape. See [parseActionReply].
         */
        private const val SPEC_ACTION_REPLY_TYPE = 0x06

        /** Payload byte of the captured F0 bootstrap command (protocol control code, not JSON). */
        private const val SPEC_BOOTSTRAP_TYPE = 0xF0

        /** Event `8.1` = live weight. Expected during a session, but never a stored result. */
        private const val SPEC_EVENT_LIVE_SIID = 0x08
        private const val SPEC_EVENT_LIVE_EIID = 0x01

        /** Event `8.2` = final settled composition result. The only storable event. */
        private const val SPEC_EVENT_RESULT_SIID = 0x08
        private const val SPEC_EVENT_RESULT_EIID = 0x02

        /**
         * `status` values the vendor's own handler refuses to save, from the S400 plugin
         * (`10466.js` event.8.2) and its formatter (`10040.js` `fmtWeightDataStatus`):
         *
         *  * 2 — 用户未匹配上(APPO): no match to a user, so no user may be credited.
         *  * 3 — 用户信息不合规(APP1): matched, but the user profile is not compliant.
         *  * 6 — 小物称重锁定: small-item lock, discarded without a result.
         *  * 7 — 超重退出: overweight exit, no report is produced.
         *
         * Everything else — 0 (normal, precise match), 1 (impedance/HR failure, weight
         * still valid) and 4 (ambiguous match) — falls into the vendor's own fallback
         * branch, which saves the packet under its `duid`. In particular status `0` is
         * deliberately *not* required: there is no user-match UI here, and status 1 still
         * carries a valid weight. Unknown values keep the vendor's fallback behaviour.
         */
        private const val STATUS_USER_NOT_MATCHED = 2
        private const val STATUS_USER_INFO_INVALID = 3
        private const val STATUS_SMALL_ITEM_LOCK = 6
        private const val STATUS_OVERWEIGHT = 7

        /**
         * Reads the MIoT spec event identity from a decrypted spec body.
         *
         * Layout, verified against the captured authenticated session (the `8e 20 19 00`
         * header followed by `07 08 02 00 01 02 00 81 a0 …`):
         *
         * ```
         *   [0..3]  proprietary header: LE16(length | 0x2000), LE16(sequence)
         *   [4]     event type      — 0x07 for an event notification (`06` = device-info reply)
         *   [5]     siid            — 0x08 for the composition/weight service
         *   [6]     eiid            — 0x01 live weight, 0x02 final settled result
         *   [7..8]  argument count / type tag
         *   [9..]   argument payload (the 32-field CSV for event 8.2)
         * ```
         *
         * Returns `null` when the bytes cannot be an event notification at all. This is the
         * explicit event-07 check: without it, a non-event spec reply would be handed to the
         * result parser and could only be rejected by accident.
         */
        internal fun specEventIdentity(plaintext: ByteArray): Triple<Int, Int, Int>? {
            if (plaintext.size <= SPEC_HEADER_LENGTH + 2) return null
            val type = plaintext[SPEC_HEADER_LENGTH].toInt() and 0xff
            if (type != SPEC_EVENT_TYPE) return null
            val siid = plaintext[SPEC_HEADER_LENGTH + 1].toInt() and 0xff
            val eiid = plaintext[SPEC_HEADER_LENGTH + 2].toInt() and 0xff
            return Triple(type, siid, eiid)
        }

        /** `true` when a decrypted spec body is the settled event.8.2 result. */
        internal fun isFinalResultEvent(plaintext: ByteArray): Boolean {
            val identity = specEventIdentity(plaintext) ?: return false
            return identity.second == SPEC_EVENT_RESULT_SIID && identity.third == SPEC_EVENT_RESULT_EIID
        }

        /**
         * `true` when a parsed result may be stored for the connection's user.
         *
         * Gated strictly on the vendor's own non-savable status set (see the constants above);
         * status `0` is not required and unknown values fall through to the vendor's fallback.
         */
        internal fun isPublishableStatus(status: Int): Boolean = when (status) {
            STATUS_USER_NOT_MATCHED,
            STATUS_USER_INFO_INVALID,
            STATUS_SMALL_ITEM_LOCK,
            STATUS_OVERWEIGHT -> false
            else -> true
        }

        // Known S400 device name patterns
        // The S400 may advertise with various names depending on firmware/region
        // Format seen in practice: "Xiaomi Scale S400 XXXX" where XXXX is last 4 of MAC
        private val KNOWN_NAME_PATTERNS = listOf(
            "SCALE S400",                  // Core pattern - matches "Xiaomi Scale S400 8E8B"
            "XMTZC14HM",                   // S400 model identifier (raw BLE name)
            "XMTZC",                       // Xiaomi scale prefix
        )

        // S400 Service UUID (Xiaomi Body Composition service)
        private val SERVICE_UUID_S400 = ParcelUuid.fromString("0000181b-0000-1000-8000-00805f9b34fb")
    }

    // Track if we've warned about missing configuration
    private var warnedMissingConfig = false

    // Broadcast-only fallback parser is retained for later compatibility work.
    private val aggregator = S400Aggregator()

    private val miotService by lazy { uuid16(0xFE95) }
    private val loginCharacteristic by lazy { uuid16(0x0010) }
    private val authCharacteristic by lazy { uuid16(0x0019) }
    private val specWriteCharacteristic by lazy { uuid16(0x001A) }
    private val specNotifyCharacteristic by lazy { uuid16(0x001B) }
    private val reassembler = S400ChannelReassembler()
    private val randomSource = SecureRandom()
    private enum class AuthState { DISCONNECTED, WAIT_MANAGEMENT, WAIT_RANDOM, WAIT_CONFIRM, WAIT_LOGIN_RESULT, READY, FAILED }
    private var authState = AuthState.DISCONNECTED
    private var appRandom: ByteArray? = null
    private var devRandom: ByteArray? = null
    private var sessionKey: ByteArray? = null
    private var session: S400StandardAuthSession? = null
    private var pendingAuthFrames: List<ByteArray>? = null
    private var pendingSpecFrames: List<ByteArray>? = null

    /**
     * Which spec message owns the (single) outbound spec transport slot.
     *
     * The device grants one fragmented message at a time: FRAGMENT_START, then its data frames,
     * then a completion ACK. Sending the 6.6 switch while the F0 bootstrap is still in flight
     * would interleave two FRAGMENT_STARTs on the same characteristic and lose one of them, so
     * the switch is only queued once the bootstrap's completion ACK has been consumed.
     */
    private enum class SpecTx { NONE, BOOTSTRAP, SWITCH_USER }

    private var specTx = SpecTx.NONE

    /**
     * Spec-envelope sequence numbers. This counter is independent of the AES-CCM counters held
     * by [session]: the envelope sequence is plaintext routing, the AES counter is the nonce.
     */
    private var specSequence = 0

    /** Sequence number carried by the 6.6 switch, used to match its op-06 reply. */
    private var switchSequence: Int? = null

    /** Sequence number of the F0 bootstrap, used to recognise its echoed reply. */
    private var bootstrapSequence: Int? = null

    /**
     * Account identity snapshot for this connection, or `null` when the user has not configured
     * one. A `null` snapshot makes the handler fail closed: it still completes the handshake (so
     * the link is diagnosable) but never switches the scale and never publishes a result.
     */
    private var identity: S400Identity? = null

    /** Outcome of the 6.6 switch, as far as the device has told us. */
    private enum class SwitchState { NOT_CONFIGURED, NOT_APPLICABLE, PENDING, ACCEPTED, REJECTED }

    private var switchState = SwitchState.NOT_CONFIGURED

    /**
     * Set once the device echoes the F0 bootstrap plaintext. The 6.6 switch is only emitted after
     * the bootstrap has both been echoed and left the outbound transport slot, so the two commands
     * can never be interleaved on the same characteristic.
     */
    private var bootstrapEchoed = false

    /** Set when the device ACKs the bootstrap's last fragment, freeing the spec write slot. */
    private var bootstrapTransportComplete = false

    /**
     * Distinct management frames seen in the current link-setup exchange.
     *
     * The vendor's channel manager sends two different management frames and only
     * then starts StandardAuth. Counting raw frames is not equivalent: a retransmit
     * or an extra management frame would advance the (or a later) counter past the
     * expected value and stall the handshake forever. Distinct frame contents are
     * compared byte-wise and the list is bounded, so duplicates are ignored and a
     * third distinct frame cannot re-trigger the transition.
     */
    private val managementSignatures = ArrayList<ByteArray>(MANAGEMENT_FRAMES_EXPECTED)

    /** User this connection was opened for; result attribution must not follow later UI changes. */
    private var sessionUser: ScaleUser? = null

    private var lastResultTime: Long? = null

    private fun writeAuth(frame: ByteArray) =
        writeTo(miotService, authCharacteristic, frame, withResponse = false)

    /**
     * Per-frame application payload capacity derived from the MTU the link actually
     * negotiated. `requestMtu()` is only a request and its result arrives after
     * `onConnected`, so the value is read at every send instead of being cached.
     * An unreported MTU falls back to the 23-byte default, never to 242.
     */
    private fun channelCapacity(): Int {
        val mtu = negotiatedMtu() ?: S400ChannelCodec.DEFAULT_ATT_MTU
        return S400ChannelCodec.payloadCapacityForMtu(mtu)
            .coerceIn(1, S400ChannelCodec.S400_PAYLOAD_CAPACITY)
    }

    /** Largest legal characteristic value for the negotiated MTU, clamped to the S400 range. */
    private fun maxFrameValueLength(): Int =
        S400ChannelCodec.maxFrameValueLengthForMtu(negotiatedMtu() ?: S400ChannelCodec.DEFAULT_ATT_MTU)
            .coerceIn(
                S400ChannelCodec.payloadCapacityForMtu(S400ChannelCodec.DEFAULT_ATT_MTU) +
                    S400ChannelCodec.HEADER_BYTES,
                S400ChannelCodec.MAX_FRAME_VALUE_LENGTH,
            )

    /**
     * Upper bound for an inbound characteristic value.
     *
     * The controller never delivers a notification larger than the negotiated MTU, so a
     * known MTU is the tighter and more accurate bound. When the transport cannot report
     * one, the S400 protocol maximum is kept instead of guessing 23: rejecting a valid
     * 244-byte management notification would break the handshake.
     */
    private fun inboundFrameBound(): Int {
        val mtu = negotiatedMtu() ?: return S400ChannelCodec.MAX_FRAME_VALUE_LENGTH
        return maxFrameValueLength()
    }

    private fun sendAuthMessage(opcode: Int, data: ByteArray) {
        // Xiaomi uses FRAGMENT_START even when the auth message fits one frame.
        val frames = S400ChannelCodec.fragment(
            opcode, data, capacity = channelCapacity(), forceFragmented = true
        )
        pendingAuthFrames = frames.drop(1)
        writeAuth(frames.first())
    }

    private fun sendSpecMessage(plaintext: ByteArray, owner: SpecTx = SpecTx.NONE) {
        val encrypted = session?.encrypt(plaintext) ?: return
        val frames = S400ChannelCodec.fragment(
            0, encrypted, capacity = channelCapacity(), forceFragmented = true
        )
        pendingSpecFrames = frames.drop(1)
        specTx = owner
        writeTo(miotService, specWriteCharacteristic, frames.first(), withResponse = false)
    }

    /** Next envelope sequence, wrapping inside the 16-bit field the header carries. */
    private fun nextSpecSequence(): Int {
        val sequence = specSequence
        specSequence = (specSequence + 1) and 0xFFFF
        return sequence
    }

    /** Send the captured F0 bootstrap; the 6.6 switch is queued behind its echo + completion. */
    private fun sendBootstrap() {
        val sequence = nextSpecSequence()
        bootstrapSequence = sequence
        bootstrapEchoed = false
        bootstrapTransportComplete = false
        sendSpecMessage(S400SpecProtocol.bootstrap(sequence), SpecTx.BOOTSTRAP)
    }

    /**
     * Emit the 6.6 switch once the bootstrap has finished on the wire.
     *
     * Two independent conditions are required, in the order the captured session shows them:
     * the device has echoed the F0 command as a decrypted spec message, and the bootstrap's
     * fragmented transfer has been completed (ACK status 0). Sending earlier would put a second
     * FRAGMENT_START on the characteristic while the bootstrap still owns it.
     *
     * Called from both edges, so it is idempotent: it only fires while [switchState] is still
     * [SwitchState.PENDING] and no switch sequence is outstanding.
     */
    private fun maybeSendSwitchUser() {
        if (!bootstrapEchoed || !bootstrapTransportComplete) return
        if (switchSequence != null) return
        val snapshot = identity ?: return
        if (switchState != SwitchState.PENDING) return
        sendSwitchUser(snapshot)
    }

    /**
     * Handle a decrypted op-`0x06` action reply.
     *
     * Only the 6.6 reply is acted on. Its `code` is the MIoT result: `0` means the firmware
     * accepted the switch, anything else is a refusal, and a truncated reply with no status byte
     * is treated as a refusal rather than as success. Replies for other siid/aiid (the device-info
     * answer, offline-record reads, …) are ignored, as are frames whose sequence does not match
     * the outstanding switch.
     */
    private fun handleActionReply(plaintext: ByteArray) {
        val reply = parseActionReply(plaintext) ?: run {
            if (plaintext.size in 5..6 && plaintext[4].toInt() == 6 &&
                (((plaintext[2].toInt() and 255) or ((plaintext[3].toInt() and 255) shl 8)) == switchSequence)) {
                switchState = SwitchState.REJECTED
                switchSequence = null
            }
            return
        }
        val expected = switchSequence ?: return
        if (reply.sequence != expected) return
        switchSequence = null
        if (reply.code == 0) {
            switchState = SwitchState.ACCEPTED
            logI("S400 switchUser acknowledged by device")
        } else {
            // code == null (no status byte) or non-zero: never assume the slot changed.
            switchState = SwitchState.REJECTED
            logW("S400 switchUser refused (status absent or non-zero)")
        }
    }

    /** `true` for the device's verbatim echo of the F0 bootstrap command. */
    private fun isBootstrapEcho(plaintext: ByteArray): Boolean =
        plaintext.size == SPEC_HEADER_LENGTH + 1 &&
            (plaintext[SPEC_HEADER_LENGTH].toInt() and 0xff) == SPEC_BOOTSTRAP_TYPE

    /**
     * Send 6.6 `switchUser` with the snapshot identity. Only called when the snapshot exists and
     * is mapped to the session's app user (see [onConnected]), so no unconfigured value can reach
     * the wire.
     */
    private fun sendSwitchUser(snapshot: S400Identity) {
        val sequence = nextSpecSequence()
        switchSequence = sequence
        switchState = SwitchState.PENDING
        sendSpecMessage(
            S400SpecCommands.switchUserFrame(sequence, snapshot.miid, snapshot.duid, snapshot.userType),
            SpecTx.SWITCH_USER,
        )
        // Identifiers are never logged; only that a switch was requested.
        logI("S400 switchUser sent (siid 6 aiid 6)")
    }

    override fun onConnected(user: ScaleUser) {
        resetGattState()
        val tokenHex = settingsGetString(SETTINGS_KEY_GATT_TOKEN)
        if (tokenHex == null || tokenHex.length != 24 || !tokenHex.all { it.digitToIntOrNull(16) != null }) {
            authState = AuthState.FAILED
            userWarn(R.string.bt_s400_missing_token)
            requestDisconnect()
            return
        }
        sessionUser = user
        // Snapshot the account identity once. It is deliberately read here and never refreshed:
        // a settings edit during the link must not re-point the publish gate mid-session.
        identity = configuredIdentity()
        if (identity == null) {
            // Fail closed: without a configured identity the device cannot be switched to this
            // user's slot, so nothing may be attributed. The handshake still runs so the failure
            // is visible and diagnosable rather than silently dropping every packet.
            switchState = SwitchState.NOT_CONFIGURED
            logW("S400 identity not configured; scale will not be switched and no result will be saved")
            userWarn(R.string.bt_s400_missing_identity)
        } else if (identity!!.appUserId != user.id) {
            // The link was opened for a user the configured identity is not mapped to. Never send
            // another account's identity, and never credit its results to this user.
            switchState = SwitchState.NOT_APPLICABLE
            logW("S400 identity is mapped to a different app user; not switching or saving")
            userWarn(R.string.bt_s400_identity_not_mapped)
        } else {
            switchState = SwitchState.PENDING
        }
        // The adapter serializes notification setup and writes in call order.
        setNotifyOn(miotService, specNotifyCharacteristic)
        setNotifyOn(miotService, specWriteCharacteristic)
        setNotifyOn(miotService, authCharacteristic)
        setNotifyOn(miotService, loginCharacteristic)
        authState = AuthState.WAIT_MANAGEMENT
        // The vendor starts its channel/MTU management exchange with 0xA4.
        writeTo(miotService, loginCharacteristic, byteArrayOf(0xA4.toByte()), withResponse = false)
    }

    /** Read the four configured identity values; `null` unless all are present and in range. */
    private fun configuredIdentity(): S400Identity? = parseIdentity(
        miid = settingsGetString(SETTINGS_KEY_MIID),
        duid = settingsGetString(SETTINGS_KEY_DUID),
        userType = settingsGetString(SETTINGS_KEY_USER_TYPE),
        appUserId = settingsGetString(SETTINGS_KEY_MAPPED_USER_ID),
    )

    override fun onNotification(characteristic: UUID, data: ByteArray, user: ScaleUser) {
        if (characteristic == loginCharacteristic) {
            if (authState == AuthState.WAIT_LOGIN_RESULT && data.contentEquals(byteArrayOf(0x21, 0, 0, 0))) {
                val key = sessionKey ?: return
                session = S400StandardAuthSession(key)
                authState = AuthState.READY
                // The captured post-login bootstrap is an encrypted Spec command;
                // GATT CCCD alone does not subscribe to MIoT event.8.2.
                sendBootstrap()
                logI("S400 StandardAuth succeeded; Spec bootstrap sent")
            } else if (authState != AuthState.READY) {
                authState = AuthState.FAILED
                requestDisconnect()
            }
            return
        }
        if (characteristic != authCharacteristic && characteristic != specNotifyCharacteristic &&
            characteristic != specWriteCharacteristic) return
        val frame = S400ChannelCodec.decode(data, maxFrameLength = inboundFrameBound()) ?: return
        if (frame is S400ChannelFrame.Ack && characteristic == authCharacteristic) {
            when (frame.status) {
                S400ChannelCodec.ACK_STATUS_CONTINUE -> {
                    val fragments = pendingAuthFrames ?: return
                    pendingAuthFrames = null
                    fragments.forEach(::writeAuth)
                }
                S400ChannelCodec.ACK_STATUS_COMPLETE -> pendingAuthFrames = null
                else -> { authState = AuthState.FAILED; requestDisconnect() }
            }
            return
        }
        if (frame is S400ChannelFrame.Ack && characteristic == specWriteCharacteristic) {
            when (frame.status) {
                S400ChannelCodec.ACK_STATUS_CONTINUE -> {
                    val fragments = pendingSpecFrames ?: return
                    pendingSpecFrames = null
                    fragments.forEach { writeTo(miotService, specWriteCharacteristic, it, withResponse = false) }
                }
                S400ChannelCodec.ACK_STATUS_COMPLETE -> {
                    pendingSpecFrames = null
                    when (specTx) {
                        SpecTx.BOOTSTRAP -> {
                            // The bootstrap's transport exchange is now finished: only here is it
                            // safe to queue 6.6 on the same characteristic.
                            specTx = SpecTx.NONE
                            bootstrapTransportComplete = true
                            maybeSendSwitchUser()
                        }
                        SpecTx.SWITCH_USER -> specTx = SpecTx.NONE
                        SpecTx.NONE -> Unit
                    }
                }
                else -> {
                    // A resend/unknown spec ack means the outbound spec stream is desynchronised.
                    // Never keep going: a half-delivered switch must not be treated as applied.
                    if (specTx == SpecTx.SWITCH_USER) switchState = SwitchState.REJECTED
                    authState = AuthState.FAILED
                    requestDisconnect()
                }
            }
            return
        }
        val stream = when (characteristic) {
            authCharacteristic -> 0x0019
            specNotifyCharacteristic -> 0x001B
            else -> 0x001A
        }
        for (event in reassembler.accept(S400ChannelDirection.DEVICE_TO_APP, stream, frame)) {
            when (event) {
                is S400ChannelEvent.AckRequired ->
                    writeTo(miotService, characteristic, S400ChannelCodec.ack(event.status), withResponse = false)
                is S400ChannelEvent.Message -> {
                    if (!event.fragmented) {
                        writeTo(miotService, characteristic, S400ChannelCodec.singleAck(), withResponse = false)
                    }
                    if (characteristic == authCharacteristic) onAuthMessage(event)
                    else if (characteristic == specNotifyCharacteristic && authState == AuthState.READY) {
                        onSpecMessage(event, user)
                    }
                }
                is S400ChannelEvent.Management -> if (!event.acknowledgement) {
                    writeTo(miotService, characteristic,
                        S400ChannelCodec.managementAck(event.packageType, event.payload), withResponse = false)
                    if (characteristic == authCharacteristic && authState == AuthState.WAIT_MANAGEMENT) {
                        // Only a management frame whose contents differ from every frame
                        // already seen may advance the handshake.
                        val isNew = managementSignatures.none {
                            it.size == event.payload.size && it.contentEquals(event.payload)
                        }
                        if (isNew && managementSignatures.size < MANAGEMENT_FRAMES_EXPECTED) {
                            managementSignatures.add(event.payload.copyOf())
                            logD("S400 channel management frame ${managementSignatures.size}/$MANAGEMENT_FRAMES_EXPECTED")
                        }
                        if (managementSignatures.size == MANAGEMENT_FRAMES_EXPECTED) {
                            authState = AuthState.WAIT_RANDOM
                            appRandom = ByteArray(16).also(randomSource::nextBytes)
                            writeTo(miotService, loginCharacteristic,
                                byteArrayOf(0x24, 0, 0, 0), withResponse = false)
                            sendAuthMessage(S400StandardAuth.OPCODE_APP_RANDOM, appRandom!!)
                        }
                    }
                }
                else -> Unit
            }
        }
    }

    private fun onAuthMessage(event: S400ChannelEvent.Message) {
        when (event.packageType) {
            S400StandardAuth.OPCODE_DEV_RANDOM -> if (authState == AuthState.WAIT_RANDOM && event.payload.size == 16) {
                val app = appRandom ?: return
                val tokenHex = settingsGetString(SETTINGS_KEY_GATT_TOKEN) ?: return
                val token = ByteArray(tokenHex.length / 2) { i ->
                    ((tokenHex[i * 2].digitToInt(16) shl 4) or tokenHex[i * 2 + 1].digitToInt(16)).toByte()
                }
                devRandom = event.payload.copyOf()
                sessionKey = S400StandardAuth.deriveSessionKey(token, app, event.payload)
                token.fill(0)
                authState = AuthState.WAIT_CONFIRM
            }
            S400StandardAuth.OPCODE_DEV_CONFIRM -> if (authState == AuthState.WAIT_CONFIRM && event.payload.size == 32) {
                val key = sessionKey ?: return
                val app = appRandom ?: return
                val dev = devRandom ?: return
                if (!S400StandardAuth.confirmationsMatch(
                        S400StandardAuth.deviceConfirmation(key, app, dev), event.payload)) {
                    authState = AuthState.FAILED
                    requestDisconnect()
                    return
                }
                val confirmation = S400StandardAuth.appConfirmation(key, app, dev)
                app.fill(0)
                dev.fill(0)
                appRandom = null
                devRandom = null
                authState = AuthState.WAIT_LOGIN_RESULT
                sendAuthMessage(S400StandardAuth.OPCODE_APP_CONFIRM, confirmation)
                confirmation.fill(0)
            }
            else -> Unit
        }
    }

    private fun onSpecMessage(event: S400ChannelEvent.Message, user: ScaleUser) {
        if (event.packageType != 0) return
        val plaintext = session?.decrypt(event.payload) ?: return

        // Action replies (op 0x06) are handled before the event gate: the 6.6 status arrives on
        // this path and is not an event notification. The F0 bootstrap is echoed verbatim instead
        // (same 5 bytes back), so it is recognised separately.
        if (isBootstrapEcho(plaintext)) {
            bootstrapEchoed = true
            logI("S400 bootstrap echoed by device; switch may follow")
            maybeSendSwitchUser()
            return
        }
        handleActionReply(plaintext)

        val eventIdentity = specEventIdentity(plaintext)
        if (eventIdentity == null) {
            // Not an event notification (e.g. the `06 …` device-info reply). Expected noise.
            logD("S400 spec reply ignored: not an event07 notification")
            return
        }
        val (_, siid, eiid) = eventIdentity
        if (siid != SPEC_EVENT_RESULT_SIID || eiid != SPEC_EVENT_RESULT_EIID) {
            // event.8.1 live weight and anything else must never be stored as a result.
            if (siid == SPEC_EVENT_LIVE_SIID && eiid == SPEC_EVENT_LIVE_EIID) {
                logD("S400 live weight event.8.1 ignored (not a settled result)")
            } else {
                logW("S400 spec event ${siid}.${eiid} ignored (not event.8.2)")
            }
            return
        }

        val csv = S400SpecProtocol.finalResultCsv(plaintext) ?: return
        val result = S400SpecMeasurement.parse(csv) ?: return

        if (!isPublishableStatus(result.status)) {
            // 2/3 mean the device did not identify this session's user, so crediting the
            // connection's user would be wrong; 6/7 carry no usable report at all.
            logW("S400 result dropped: device status ${result.status} is not user-attributable")
            return
        }

        // Attribution gate. A result is only stored when the device reports back exactly the
        // identity this connection switched it to. Without a configured identity, or after a
        // refused switch, nothing is written — the previous behaviour of crediting the
        // connection's user is deliberately removed, because a scale that is still on another
        // account's slot echoes *that* account's ids and would otherwise be misfiled here.
        val snapshot = identity ?: run {
            logW("S400 result dropped: no account mapping configured")
            return
        }
        if (switchState == SwitchState.REJECTED) {
            logW("S400 result dropped: device refused the account switch")
            return
        }
        if (!identityMatches(snapshot, result)) {
            // Includes the case where the device never applied the switch: the echoed ids are
            // another account's, so the packet belongs to that account, not to this user.
            logW("S400 result dropped: device-reported identity does not match the configured account")
            return
        }
        val owner = sessionUser ?: user
        if (owner.id != snapshot.appUserId) {
            // The link was opened for a user the configured identity is not mapped to.
            logW("S400 result dropped: configured identity is not mapped to this app user")
            return
        }
        if (lastResultTime == result.timeSeconds) return
        lastResultTime = result.timeSeconds

        val measurement = ScaleMeasurement().apply {
            dateTime = Date()
            userId = owner.id
            // What the S400 measures is never carried over from an earlier weigh-in, whether or
            // not this packet had it: a missing value is unknown, not unchanged.
            noCarryOver += S400_MEASURED_KEYS
            this[MeasurementType.WEIGHT] = Kg(result.weightKg)
            result.heartRate?.let { this[MeasurementType.HEART_RATE] = Bpm(it) }
            // Body composition is only a measurement when the scale got an impedance reading.
            // Without it the packet holds a weight and fields the firmware did not compute;
            // publishing those would invite openScale's carry-over to fill the gaps from the
            // previous weigh-in, producing a row that mixes two sessions.
            if (result.hasComposition) {
                this[MeasurementType.BODY_FAT] = Percent(result.bodyFatPercent)
                this[MeasurementType.WATER] = Percent(result.bodyWaterPercent)
                // Xiaomi Home shows field 24 (`slp`) as the muscle percentage; field 13 (`smm`)
                // is skeletal muscle in kg and gives a different, much lower percentage. Prefer
                // what the vendor app shows; fall back to smm only if the scale sent no `slp`.
                this[MeasurementType.MUSCLE] = Percent(
                    result.musclePercent ?: (result.skeletalMuscleKg / result.weightKg * 100f)
                )
                this[MeasurementType.BONE] = Kg(result.boneMassKg)
                this[MeasurementType.LBM] = Kg(result.fatFreeMassKg)
                this[MeasurementType.VISCERAL_FAT] = result.visceralFatLevel.toFloat()
                this[MeasurementType.BMR] = Kcal(result.bmrKcal.toFloat())
                this[MeasurementType.PROTEIN] = Percent(result.proteinPercent)
                this[MeasurementType.IMPEDANCE] = Ohm(result.impedanceHighOhm)
                this[MeasurementType.IMPEDANCE_LOW] = Ohm(result.impedanceLowOhm)
                this[METABOLIC_AGE] = result.metabolicAge
                // Not in the packet we use: Xiaomi derives it from the profile, so do the same.
                standardWeightKg(owner.bodyHeight, owner.gender == GenderType.MALE)
                    ?.let { this[IDEAL_WEIGHT] = Kg(it) }
            }
        }
        if (!result.hasComposition) {
            logW("S400 result has no impedance; publishing weight only (pulse if the packet has one)")
        }
        publish(measurement)
        logI("S400 authenticated device result published")
    }

    private fun resetGattState() {
        appRandom?.fill(0)
        devRandom?.fill(0)
        sessionKey?.fill(0)
        appRandom = null
        devRandom = null
        sessionKey = null
        session = null
        pendingAuthFrames = null
        pendingSpecFrames = null
        managementSignatures.forEach { it.fill(0) }
        managementSignatures.clear()
        sessionUser = null
        lastResultTime = null
        identity = null
        switchState = SwitchState.NOT_CONFIGURED
        switchSequence = null
        bootstrapSequence = null
        bootstrapEchoed = false
        bootstrapTransportComplete = false
        specTx = SpecTx.NONE
        specSequence = 0
        reassembler.reset()
        authState = AuthState.DISCONNECTED
    }

    override fun onDisconnected() = resetGattState()


    @Composable
    override fun DeviceConfigurationUi() {
        // 1. Read the initial value from settings
        val persistedValue = settingsGetString(SETTINGS_KEY_BIND_KEY) ?: ""

        // 2. Track the local input and a "isSaved" flag for immediate feedback
        var inputValue by remember(persistedValue) { mutableStateOf(persistedValue) }
        var lastSavedValue by remember { mutableStateOf(persistedValue) }
        // Store the GATT token separately from the advertisement bind key.
        val persistedToken = settingsGetString(SETTINGS_KEY_GATT_TOKEN) ?: ""
        var tokenInput by remember(persistedToken) { mutableStateOf(persistedToken) }
        var lastSavedToken by remember { mutableStateOf(persistedToken) }
        val tokenValid = tokenInput.length == 24 && tokenInput.all { it in '0'..'9' || it in 'a'..'f' }
        val tokenError = tokenInput.isNotEmpty() && !tokenValid
        LaunchedEffect(tokenInput) {
            if (tokenValid && tokenInput != lastSavedToken) {
                settingsPutString(SETTINGS_KEY_GATT_TOKEN, tokenInput)
                lastSavedToken = tokenInput
            }
        }

        // Validation logic
        val isValid = inputValue.length == 32
        val showError = inputValue.isNotEmpty() && !isValid
        // Logic: It's saved if it's valid and matches the last value we successfully wrote
        val isSuccessfullySaved = isValid && inputValue == lastSavedValue && inputValue.isNotEmpty()

        // Auto-save effect
        LaunchedEffect(inputValue) {
            if (isValid && inputValue != lastSavedValue) {
                // Never write device credentials to Android logs.
                settingsPutString(SETTINGS_KEY_BIND_KEY, inputValue)
                // Update the local "last saved" state immediately to trigger UI feedback
                lastSavedValue = inputValue
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.s400_bind_key_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedTextField(
                value = inputValue,
                onValueChange = { newValue ->
                    val filtered = newValue
                        .filter { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
                        .lowercase()
                    if (filtered.length <= 32) {
                        inputValue = filtered
                    }
                },
                label = { Text(stringResource(R.string.s400_bind_key_label)) },
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = { Icon(Icons.Default.Key, contentDescription = null) },
                singleLine = true,
                isError = showError,
                supportingText = {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        if (showError) {
                            Text(stringResource(R.string.s400_bind_key_error))
                        } else if (isSuccessfullySaved) {
                            Text(
                                text = stringResource(R.string.saved),
                                color = MaterialTheme.colorScheme.primary
                            )
                        } else {
                            Spacer(modifier = Modifier.weight(1f))
                        }
                        Text("${inputValue.length}/32")
                    }
                }
            )
            Text(
                text = stringResource(R.string.s400_token_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = tokenInput,
                onValueChange = { proposed ->
                    val hex = proposed.filter { it.isDigit() || it.lowercaseChar() in 'a'..'f' }.lowercase()
                    if (hex.length <= 24) tokenInput = hex
                },
                label = { Text(stringResource(R.string.s400_token_label)) },
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = { Icon(Icons.Default.Key, contentDescription = null) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                isError = tokenError,
                supportingText = {
                    Text(if (tokenError) stringResource(R.string.s400_token_error)
                         else "${tokenInput.length}/24")
                }
            )

            // ---- Xiaomi account mapping ------------------------------------------------
            // Existing profiles only: the user enters the identifiers of an account that
            // already exists in Xiaomi Home. Nothing here creates an account or uploads data.
            Text(
                text = stringResource(R.string.s400_identity_title),
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = stringResource(R.string.s400_identity_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            val persistedMiid = settingsGetString(SETTINGS_KEY_MIID) ?: ""
            var miidInput by remember(persistedMiid) { mutableStateOf(persistedMiid) }
            var lastSavedMiid by remember { mutableStateOf(persistedMiid) }
            val miidValid = miidInput.isNotEmpty() &&
                miidInput.all { it.isDigit() } && (miidInput.toLongOrNull() ?: 0L) > 0L
            LaunchedEffect(miidInput) {
                if (miidValid && miidInput != lastSavedMiid) {
                    settingsPutString(SETTINGS_KEY_MIID, miidInput)
                    lastSavedMiid = miidInput
                }
            }
            OutlinedTextField(
                value = miidInput,
                onValueChange = { proposed ->
                    val digits = proposed.filter { it.isDigit() }
                    if (digits.length <= 20) miidInput = digits
                },
                label = { Text(stringResource(R.string.s400_identity_miid_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = miidInput.isNotEmpty() && !miidValid,
                supportingText = {
                    Text(
                        when {
                            miidInput.isNotEmpty() && !miidValid ->
                                stringResource(R.string.s400_identity_miid_error)
                            miidValid && miidInput == lastSavedMiid -> stringResource(R.string.saved)
                            else -> ""
                        }
                    )
                }
            )

            val persistedDuid = settingsGetString(SETTINGS_KEY_DUID) ?: ""
            var duidInput by remember(persistedDuid) { mutableStateOf(persistedDuid) }
            var lastSavedDuid by remember { mutableStateOf(persistedDuid) }
            val duidValid = duidInput.isNotEmpty() &&
                duidInput.all { it.isDigit() } && (duidInput.toIntOrNull() ?: -1) in 0..255
            LaunchedEffect(duidInput) {
                if (duidValid && duidInput != lastSavedDuid) {
                    settingsPutString(SETTINGS_KEY_DUID, duidInput)
                    lastSavedDuid = duidInput
                }
            }
            OutlinedTextField(
                value = duidInput,
                onValueChange = { proposed ->
                    val digits = proposed.filter { it.isDigit() }
                    if (digits.length <= 3) duidInput = digits
                },
                label = { Text(stringResource(R.string.s400_identity_duid_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = duidInput.isNotEmpty() && !duidValid,
                supportingText = {
                    Text(
                        if (duidInput.isNotEmpty() && !duidValid)
                            stringResource(R.string.s400_identity_duid_error)
                        else if (duidValid && duidInput == lastSavedDuid)
                            stringResource(R.string.saved)
                        else ""
                    )
                }
            )

            val persistedUserType = settingsGetString(SETTINGS_KEY_USER_TYPE) ?: ""
            var userTypeInput by remember(persistedUserType) { mutableStateOf(persistedUserType) }
            var lastSavedUserType by remember { mutableStateOf(persistedUserType) }
            val userTypeValid = userTypeInput.isNotEmpty() &&
                userTypeInput.all { it.isDigit() } && (userTypeInput.toIntOrNull() ?: -1) in 0..MAX_USER_TYPE
            LaunchedEffect(userTypeInput) {
                if (userTypeValid && userTypeInput != lastSavedUserType) {
                    settingsPutString(SETTINGS_KEY_USER_TYPE, userTypeInput)
                    lastSavedUserType = userTypeInput
                }
            }
            OutlinedTextField(
                value = userTypeInput,
                onValueChange = { proposed ->
                    val digits = proposed.filter { it.isDigit() }
                    if (digits.length <= 1) userTypeInput = digits
                },
                label = { Text(stringResource(R.string.s400_identity_user_type_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = userTypeInput.isNotEmpty() && !userTypeValid,
                supportingText = {
                    Text(
                        if (userTypeInput.isNotEmpty() && !userTypeValid)
                            stringResource(R.string.s400_identity_user_type_error)
                        else stringResource(R.string.s400_identity_user_type_hint)
                    )
                }
            )

            val persistedMappedUser = settingsGetString(SETTINGS_KEY_MAPPED_USER_ID) ?: ""
            var mappedUserInput by remember(persistedMappedUser) { mutableStateOf(persistedMappedUser) }
            var lastSavedMappedUser by remember { mutableStateOf(persistedMappedUser) }
            val mappedUserValid = mappedUserInput.isNotEmpty() &&
                mappedUserInput.all { it.isDigit() } && (mappedUserInput.toIntOrNull() ?: 0) > 0
            LaunchedEffect(mappedUserInput) {
                if (mappedUserValid && mappedUserInput != lastSavedMappedUser) {
                    settingsPutString(SETTINGS_KEY_MAPPED_USER_ID, mappedUserInput)
                    lastSavedMappedUser = mappedUserInput
                }
            }
            OutlinedTextField(
                value = mappedUserInput,
                onValueChange = { proposed ->
                    val digits = proposed.filter { it.isDigit() }
                    if (digits.length <= 10) mappedUserInput = digits
                },
                label = { Text(stringResource(R.string.s400_identity_mapped_user_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = mappedUserInput.isNotEmpty() && !mappedUserValid,
                supportingText = {
                    Text(
                        if (mappedUserInput.isNotEmpty() && !mappedUserValid)
                            stringResource(R.string.s400_identity_mapped_user_error)
                        else stringResource(R.string.s400_identity_mapped_user_hint)
                    )
                }
            )

            // Overall state. Only the masked account suffix is ever shown, and only once the
            // whole mapping is complete and persisted.
            val mappingComplete = miidValid && duidValid && userTypeValid && mappedUserValid
            val mappingStarted = miidInput.isNotEmpty() || duidInput.isNotEmpty() ||
                userTypeInput.isNotEmpty() || mappedUserInput.isNotEmpty()

            if (mappingComplete) {
                Text(
                    text = stringResource(R.string.s400_identity_configured, maskAccountId(miidInput)),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodySmall
                )
            } else if (mappingStarted) {
                Text(
                    text = stringResource(R.string.s400_identity_incomplete),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }

    override fun supportFor(device: ScannedDeviceInfo): DeviceSupport? {
        val name = device.name.uppercase(Locale.ROOT)

        // Check if device name matches known S400 patterns
        // Use contains() for flexibility - some names may have prefixes/suffixes
        val isS400 = KNOWN_NAME_PATTERNS.any { pattern ->
            val upperPattern = pattern.uppercase(Locale.ROOT)
            name.contains(upperPattern) || name.startsWith(upperPattern)
        }

        if (!isS400) return null

        return DeviceSupport(
            displayName = "Xiaomi Body Composition Scale S400",
            capabilities = setOf(
                DeviceCapability.LIVE_WEIGHT_STREAM,
                DeviceCapability.BODY_COMPOSITION
            ),
            implemented = setOf(
                DeviceCapability.LIVE_WEIGHT_STREAM,
                DeviceCapability.BODY_COMPOSITION
            ),
            tuningProfile = TuningProfile.Balanced,
            linkMode = LinkMode.CONNECT_GATT
        )
    }

    /**
     * Process BLE advertisements from the S400 scale.
     *
     * The S400 sends encrypted service data that we need to decrypt
     * using the user's bind key and the scale's MAC address.
     */
    override fun onAdvertisement(result: ScanResult, user: ScaleUser): BroadcastAction {
        // Get configured bind key and MAC address
        val bindKey = settingsGetString(SETTINGS_KEY_BIND_KEY)
        val configuredMac = settingsGetString(SETTINGS_KEY_MAC_ADDRESS)

        // Get MAC from scan result (format: XX:XX:XX:XX:XX:XX)
        val deviceMac = result.device.address

        // Use configured MAC if available, otherwise use detected MAC
        val macAddress = if (!configuredMac.isNullOrEmpty() && S400Decryptor.isValidMacAddress(configuredMac)) {
            configuredMac
        } else {
            deviceMac
        }

        // Validate configuration
        if (bindKey.isNullOrEmpty() || !S400Decryptor.isValidBindKey(bindKey)) {
            if (!warnedMissingConfig) {
                logW("S400: Missing or invalid bind key. Configure in Settings.")
                userWarn(R.string.bt_s400_missing_bind_key)
                warnedMissingConfig = true
            }
            return BroadcastAction.IGNORED
        }

        // Extract service data from advertisement
        val serviceData = extractServiceData(result) ?: return BroadcastAction.IGNORED

        logD("S400 advert: ${serviceData.size} bytes from $deviceMac")

        // Attempt decryption
        val measurement = try {
            S400Decryptor.decrypt(serviceData, macAddress, bindKey)
        } catch (e: Exception) {
            logW("S400 decryption failed: ${e.message}")
            return BroadcastAction.IGNORED
        }

        if (measurement == null) {
            logD("S400: No valid measurement in advertisement")
            return BroadcastAction.IGNORED
        }

        logD(
            "S400 packet: weight=${measurement.weightKg}kg, " +
                "impedanceHigh=${measurement.impedanceHigh}, " +
                "impedanceLow=${measurement.impedanceLow}, " +
                "hr=${measurement.heartRate}"
        )

        val finalized = when (val outcome = aggregator.ingest(deviceMac, measurement, System.currentTimeMillis())) {
            is S400Aggregator.Outcome.Pending -> return BroadcastAction.CONSUMED_KEEP_SCANNING
            is S400Aggregator.Outcome.Duplicate -> return BroadcastAction.CONSUMED_KEEP_SCANNING
            is S400Aggregator.Outcome.Finalized -> outcome
        }

        logI(
            "S400 finalized: weight=${finalized.weightKg}kg, " +
                "impedanceHigh=${finalized.impedanceHigh}, " +
                "impedanceLow=${finalized.impedanceLow}, " +
                "hr=${finalized.heartRate}, timedOut=${finalized.timedOut}"
        )

        val composition = S400BodyComposition.compute(
            S400Inputs(
                age = user.age,
                sexMale = user.gender == GenderType.MALE,
                heightCm = user.bodyHeight,
                weightKg = finalized.weightKg,
                rHighRaw = finalized.impedanceHigh,
                // Single-band fallback when Packet B never arrives (older firmware path).
                rLowRaw = finalized.impedanceLow ?: finalized.impedanceHigh,
            ),
        )

        // Body fat: use the server-verified v235 model (339/356 exact against real
        // Xiaomi /eco/scale/bcalc responses — see docs/s400_v235_body_fat_recovery.md).
        // Falls back to the Holtek-derived S400BodyComposition estimate only when the
        // user's profile falls outside the verified input domain (returns null there),
        // so a result is still shown rather than nothing.
        //
        // KNOWN INCONSISTENCY: bone/muscle/FFM below still derive internally from
        // S400BodyComposition's own (unverified, Holtek-sourced) body fat % — they are
        // NOT recomputed from verifiedBodyFatPct. Until those are independently verified
        // against the oracle too, the displayed BODY_FAT may not arithmetically match
        // BONE + MUSCLE + fat mass. Do not "fix" this by feeding verifiedBodyFatPct into
        // S400BodyComposition without first validating bone/muscle/water/visceral fat
        // the same way body fat was validated here.
        val verifiedBodyFatPct = S400BodyFatV235.estimate(
            heightCm = user.bodyHeight,
            weightKg = finalized.weightKg,
            ageYears = user.age,
            sexMale = user.gender == GenderType.MALE,
            impedanceHighOhm = finalized.impedanceHigh,
        )

        val scaleMeasurement = ScaleMeasurement().apply {
            dateTime = Date()
            userId = user.id
            this[MeasurementType.WEIGHT] = Kg(finalized.weightKg)
            finalized.heartRate?.let { this[MeasurementType.HEART_RATE] = Bpm(it) }
            this[MeasurementType.IMPEDANCE] = Ohm(finalized.impedanceHigh.toFloat())
            finalized.impedanceLow?.let { this[MeasurementType.IMPEDANCE_LOW] = Ohm(it.toFloat()) }

            this[MeasurementType.BODY_FAT] = Percent(verifiedBodyFatPct ?: composition.bfPct ?: 0f)
            this[MeasurementType.WATER] = Percent(composition.tbwPct ?: 0f)
            this[MeasurementType.MUSCLE] = Percent(composition.smmPct ?: 0f)
            this[MeasurementType.BONE] = Kg(composition.boneKg ?: 0f)
            this[MeasurementType.LBM] = Kg(composition.ffmKg ?: 0f)
            this[MeasurementType.VISCERAL_FAT] = composition.vfi ?: 0f
            this[MeasurementType.BMR] = Kcal(composition.bmrKcal ?: 0f)
            this[MeasurementType.PROTEIN] = Percent(composition.proteinPct ?: 0f)

            // S400-exclusive metrics from Holtek + l56 secondary calculator.
            composition.metabolicAge?.let { this[METABOLIC_AGE] = it }
            composition.idealWeightKg?.let { this[IDEAL_WEIGHT] = Kg(it) }

        }

        publish(scaleMeasurement)

        return BroadcastAction.CONSUMED_STOP
    }

    /**
     * Extract service data from the BLE scan result.
     *
     * The S400 sends data via Service Data (AD type 0x16) for the
     * Body Composition Service UUID (0x181B).
     */
    private fun extractServiceData(result: ScanResult): ByteArray? {
        val scanRecord = result.scanRecord ?: return null

        // Try to get service data for the Body Composition Service
        val serviceData = scanRecord.serviceData

        // Check for 0x181B service data
        serviceData?.get(SERVICE_UUID_S400)?.let { data ->
            if (data.size >= 24) {
                return data
            }
        }

        // Some devices may include the service UUID in the data
        // Try all service data entries
        serviceData?.values?.forEach { data ->
            if (data.size >= 24 && data.size <= 26) {
                return data
            }
        }

        // Fallback: check raw advertisement bytes for service data
        val rawBytes = scanRecord.bytes
        if (rawBytes != null && rawBytes.size >= 26) {
            // Look for service data AD type (0x16) followed by 0x1B 0x18 (little-endian 0x181B)
            for (i in 0 until rawBytes.size - 26) {
                if (rawBytes[i] == 0x16.toByte() &&
                    rawBytes[i + 1] == 0x1B.toByte() &&
                    rawBytes[i + 2] == 0x18.toByte()) {
                    // Found service data header, extract the data
                    val dataStart = i + 3
                    val remaining = rawBytes.size - dataStart
                    if (remaining >= 24) {
                        return rawBytes.copyOfRange(dataStart, dataStart + minOf(remaining, 26))
                    }
                }
            }
        }

        return null
    }
}
