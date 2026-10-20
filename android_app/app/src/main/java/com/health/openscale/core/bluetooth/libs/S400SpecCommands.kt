/*
 * openScale
 * Copyright (C) 2025 olie.xdev <olie.xdeveloper@googlemail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.health.openscale.core.bluetooth.libs

/**
 * Post-login MIoT Spec **action** commands for the S400, as pure Kotlin/JVM.
 *
 * ## Evidence
 *
 * The byte layout below is not inferred from vendor naming conventions. It was
 * confirmed by decrypting real S400 Spec-channel traffic (AES-CCM, 4-byte tag)
 * captured on the characteristic at handle `0x0027`/`0x002A` and then matching
 * each plaintext against the vendor encoder and the RN bundle:
 *
 *  * native encoder: `_m_j.v38` (`DoActionPacket`), `_m_j.tip`
 *    (`SetPropertyPacket`) and `_m_j.ccp` (`OooOO0o`/`OooOOO0`) in
 *    `classes78.dex`;
 *  * RN producer: `SpecGenerator` (Metro module `10208`) in `main.bundle`.
 *
 * Verified plaintext envelopes (byte-for-byte, all 4 captured in two sessions):
 *
 * ```text
 * 13.1 user sync   len=120  op=5 siid=13 aiid=1 count=5  piids 1,2,4,3,5
 * 13.1 user sync   len=273  op=5 siid=13 aiid=1 count=5  piids 1,2,4,3,5  (+ ud array)
 * 6.6  switch user len= 30  op=5 siid= 6 aiid=6 count=3  piids 1,8,4
 * 6.5  basic weight len=36  op=5 siid= 6 aiid=5 count=4  piids 1,8,4,6
 * ```
 *
 * The `piid` order is the order of the `objects` array in the JS entity, not a
 * sorted order — 13.1 emits `1, 2, 4, 3, 5` because the bundle builds
 * `[prop1, prop2, prop4, prop3, prop5]`. That specific ordering is reproduced
 * deliberately.
 *
 * ## Spec action body (op 5)
 *
 * ```text
 * siid   u8
 * aiid   u8
 * count  u8
 * repeat count:
 *   piid  u16 LE                property id
 *   desc  u16 LE                (valueType << 12) | valueByteLength
 *   value bytes LE              length from desc
 * ```
 *
 * `desc` high nibble is the value type code, low 12 bits the value byte length;
 * observed words are `0x8008` (INT64/8), `0x1001` (UINT8/1), `0x3002`
 * (UINT16/2), `0x5004` (UINT32/4), `0x0001` (BOOL/1), `0xA0ED` and `0xA054`
 * (STRING/237 and /84). This class does not encrypt and never sees a key: pass
 * the result to the AES-CCM layer, then to [S400ChannelCodec].
 */
object S400SpecCommands {

    /** Spec operation code for an action request. */
    const val OP_ACTION = 5

    /** Spec operation code for a set-properties request. */
    const val OP_SET_PROPERTIES = 0

    /** `siid` of the user/account service. */
    const val SIID_USER = 6

    /** `siid` of the weighing-mode service (setProperties target). */
    const val SIID_MODE = 10

    /** `piid` of the weighing mode inside [SIID_MODE]. */
    const val PIID_MODE = 1

    /** `siid` of the device-info service. */
    const val SIID_DEVICE = 13

    /** `siid` of the offline-record service. */
    const val SIID_RECORD = 9

    /** `siid` of the shared-user service. */
    const val SIID_SHARED_USER = 14

    /** Action ids observed on [SIID_USER]. */
    const val AIID_USER_ADD = 1

    const val AIID_USER_DELETE = 3

    const val AIID_USER_BASIC_WEIGHT = 5

    const val AIID_USER_SWITCH = 6

    /** Action id of the 13.1 device-info / user-list sync. */
    const val AIID_DEVICE_SYNC = 1

    /** Longest string the vendor encoder accepts for a STRING value. */
    const val MAX_STRING_BYTES = 1024

    /**
     * MIoT value type codes, as defined by the vendor enum
     * `com.miot.spec.entity.SpecValueType` (`bitValue`, `byteLength`).
     */
    enum class ValueType(val code: Int, val byteLength: Int) {
        BOOL(0, 1),
        UINT8(1, 1),
        INT8(2, 1),
        UINT16(3, 2),
        INT16(4, 2),
        UINT32(5, 4),
        INT32(6, 4),
        UINT64(7, 8),
        INT64(8, 8),
        FLOAT(9, 4),
        STRING(10, 0);

        /** True when the value is carried as a fixed-width integer. */
        val isInteger: Boolean get() = this != FLOAT && this != STRING && this != BOOL
    }

    /** One `objects[]` entry of an action entity. */
    sealed class Property {
        abstract val piid: Int
        abstract val type: ValueType

        data class Bool(override val piid: Int, val value: Boolean) : Property() {
            override val type get() = ValueType.BOOL
        }

        data class UInt8(override val piid: Int, val value: Int) : Property() {
            override val type get() = ValueType.UINT8
        }

        data class Int8(override val piid: Int, val value: Int) : Property() {
            override val type get() = ValueType.INT8
        }

        data class UInt16(override val piid: Int, val value: Int) : Property() {
            override val type get() = ValueType.UINT16
        }

        data class Int16(override val piid: Int, val value: Int) : Property() {
            override val type get() = ValueType.INT16
        }

        data class UInt32(override val piid: Int, val value: Long) : Property() {
            override val type get() = ValueType.UINT32
        }

        data class Int32(override val piid: Int, val value: Int) : Property() {
            override val type get() = ValueType.INT32
        }

        data class UInt64(override val piid: Int, val value: Long) : Property() {
            override val type get() = ValueType.UINT64
        }

        data class Int64(override val piid: Int, val value: Long) : Property() {
            override val type get() = ValueType.INT64
        }

        data class Float32(override val piid: Int, val value: Float) : Property() {
            override val type get() = ValueType.FLOAT
        }

        data class Text(override val piid: Int, val value: String) : Property() {
            override val type get() = ValueType.STRING
        }
    }

    /** One row of the 13.1 `ud` array. */
    data class UserRow(
        val uid: Int,
        val userType: Int,
        val age: Int,
        val sex: Int,
        val heightCm: Int,
        val targetWeight100g: Int,
        val updatedAtEpochSeconds: Long,
    ) {
        /**
         * Compact JSON object with the bundle's key order
         * (`uid, ut, age, sex, hi, wt, time`) and no whitespace, i.e. exactly
         * what `JSON.stringify` produces for the object built in
         * `updateInfo2Device`.
         */
        fun toJson(): String = buildString(64) {
            append("{\"uid\":").append(uid)
            append(",\"ut\":").append(userType)
            append(",\"age\":").append(age)
            append(",\"sex\":").append(sex)
            append(",\"hi\":").append(heightCm)
            append(",\"wt\":").append(targetWeight100g)
            append(",\"time\":").append(updatedAtEpochSeconds)
            append('}')
        }
    }

    /**
     * The JSON string of the 13.1 `piid 5` property.
     *
     * `mid` is a **string** (the bundle passes `Service.account.ID` straight
     * into `JSON.stringify`), `uid`/`uc`/`ow` are numbers and `hash` is the
     * lowercase MD5 hex of the `ud` array. `ud` is only present when the cached
     * hash differs from [hash]; a hash-only sync reproduces the observed
     * 84-byte string, a two-row sync the observed 237-byte one.
     */
    fun userSyncJson(
        mid: String,
        masterUid: Int,
        userCount: Int,
        isOwner: Boolean,
        hash: String,
        users: List<UserRow>? = null,
    ): String = buildString(64 + (users?.size ?: 0) * 64) {
        append("{\"mid\":\"").append(mid)
        append("\",\"uid\":").append(masterUid)
        append(",\"uc\":").append(userCount)
        append(",\"ow\":").append(if (isOwner) 1 else 0)
        append(",\"hash\":\"").append(hash).append('"')
        if (users != null) {
            append(",\"ud\":[")
            users.forEachIndexed { index, row ->
                if (index > 0) append(',')
                append(row.toJson())
            }
            append(']')
        }
        append('}')
    }

    /**
     * `hash` of a 13.1 sync: lowercase MD5 hex of the compact `ud` array JSON.
     *
     * Verified: recomputing this over the decrypted `ud` array of the captured
     * 273-byte frame reproduces the `hash` string carried in the same frame.
     */
    fun userSyncHash(users: List<UserRow>): String {
        val json = buildString(users.size * 64 + 2) {
            append('[')
            users.forEachIndexed { index, row ->
                if (index > 0) append(',')
                append(row.toJson())
            }
            append(']')
        }
        return md5Hex(json.toByteArray(Charsets.UTF_8))
    }

    // ---- entity builders (mirror SpecGenerator in Metro module 10208) ------

    /**
     * `genSwitchUserSpec` -> 6.6. Emits exactly 30 plaintext bytes and the
     * piid order `1, 8, 4`.
     */
    fun switchUser(miid: Long, uid: Int, userType: Int): List<Property> = listOf(
        Property.Int64(1, miid),
        Property.UInt8(8, uid),
        Property.UInt8(4, userType),
    )

    /**
     * `genBasicWeightSpec` -> 6.5. Emits exactly 36 plaintext bytes; the base
     * weight is a UINT16 in 100 g units (`873` == 87.3 kg on the wire).
     */
    fun basicWeight(miid: Long, uid: Int, userType: Int, weight100g: Int): List<Property> = listOf(
        Property.Int64(1, miid),
        Property.UInt8(8, uid),
        Property.UInt8(4, userType),
        Property.UInt16(6, weight100g),
    )

    /** `genDeleteUserSpec` -> 6.3. */
    fun deleteUser(miid: Long, uid: Int, userType: Int): List<Property> = listOf(
        Property.Int64(1, miid),
        Property.UInt8(8, uid),
        Property.UInt8(4, userType),
    )

    /**
     * `genAddUser` -> 6.1. Order matches the bundle's `props.push` sequence:
     * `1, 8, 13, 4, 2, 3, 5, 6, 7, 9, 10`.
     *
     * Not exercised by any capture in this investigation, so it is derived
     * from source only; treat it as source-verified, not wire-verified.
     */
    fun addUser(
        miid: Long,
        uid: Int,
        isOwner: Boolean,
        userType: Int,
        age: Int,
        sex: Int,
        heightCm: Int,
        weight100g: Int,
        updatedAtEpochSeconds: Long,
        bodyFatPercent100: Int,
        appVersion: Long,
    ): List<Property> = listOf(
        Property.Int64(1, miid),
        Property.UInt8(8, uid),
        Property.Bool(13, isOwner),
        Property.UInt8(4, userType),
        Property.UInt8(2, age),
        Property.UInt8(3, sex),
        Property.UInt8(5, heightCm),
        Property.UInt16(6, weight100g),
        Property.UInt32(7, updatedAtEpochSeconds),
        Property.UInt16(9, bodyFatPercent100),
        Property.UInt32(10, appVersion),
    )

    /**
     * 13.1 device-info / user-list sync.
     *
     * Property order `1, 2, 4, 3, 5` with types UINT16, UINT8, UINT32, BOOL,
     * STRING — copied from the bundle's `[prop1, prop2, prop4, prop3, prop5]`
     * and confirmed against both captured frames.
     *
     * @param appVersion the bundle sends `Package.version` here; 31 was observed.
     */
    fun deviceSync(
        appVersion: Int,
        unit: Int,
        timestampEpochSeconds: Long,
        isOn: Boolean,
        json: String,
    ): List<Property> = listOf(
        Property.UInt16(1, appVersion),
        Property.UInt8(2, unit),
        Property.UInt32(4, timestampEpochSeconds),
        Property.Bool(3, isOn),
        Property.Text(5, json),
    )

    // ---- setProperties (op 0) ---------------------------------------------
    //
    // Source-verified from the vendor encoder `_m_j.tip` (SetPropertyPacket):
    //   6-byte header: LE16(len|0x2000) LE16(seq) 0x00 count
    //   per property : siid u8 | piid u16 LE | desc u16 LE | value
    // Note this carries a *per-property* siid, unlike the op-5 action body
    // which carries a single siid/aiid in its header.
    //
    // No setProperties frame appears in the captures used for this
    // investigation, so unlike the op-5 encoders above this path is
    // source-verified only and is not covered by a wire byte-for-byte check.

    /** One `objects[]` entry of a setProperties entity. */
    data class WriteProperty(
        val siid: Int,
        val piid: Int,
        val type: S400SpecCommands.ValueType,
        val value: Any,
    )

    /**
     * `devEnterMode(mode)` — weighing mode. The bundle builds
     * `{objects:[{siid:10, piid:1, value:mode, type:1}]}`, a 12-byte plaintext.
     */
    fun enterMode(mode: Int): List<WriteProperty> = listOf(
        WriteProperty(SIID_MODE, PIID_MODE, ValueType.UINT8, mode),
    )

    /** Encode the op-0 body: `count u8` then one `siid|piid|desc|value` per entry. */
    fun encodeSetPropertiesBody(properties: List<WriteProperty>): ByteArray {
        require(properties.size <= 255) { "property count out of [0,255]" }
        require(properties.map { it.siid to it.piid }.toSet().size == properties.size) {
            "duplicate siid/piid in setProperties entity"
        }
        val parts = properties.map { encodeWriteProperty(it) }
        val total = 1 + parts.sumOf { it.size }
        val out = ByteArray(total)
        out[0] = properties.size.toByte()
        var offset = 1
        for (part in parts) {
            System.arraycopy(part, 0, out, offset, part.size)
            offset += part.size
        }
        return out
    }

    /** Encode one setProperties entry: `siid u8 | piid u16 | desc u16 | value`. */
    fun encodeWriteProperty(property: WriteProperty): ByteArray {
        val value = rawValueBytes(property.type, property.value)
        require(value.size <= 0xFFF) { "value length ${value.size} does not fit in 12 bits" }
        val desc = (property.type.code shl 12) or value.size
        val out = ByteArray(5 + value.size)
        out[0] = property.siid.toByte()
        putLe16(out, 1, property.piid)
        putLe16(out, 3, desc)
        System.arraycopy(value, 0, out, 5, value.size)
        return out
    }

    /**
     * Encode a complete setProperties plaintext frame:
     * `LE16(len|0x2000) LE16(sequence) 0x00 body`.
     *
     * The vendor `tip.OooO()` seeds its running total at 6 — the header is
     * `len(2) seq(2) op(1) count(1)` — so the length field covers the whole
     * frame including its own header.
     */
    fun encodeSetPropertiesFrame(sequence: Int, properties: List<WriteProperty>): ByteArray {
        val body = encodeSetPropertiesBody(properties)
        val total = body.size + 5
        require(total <= 0xFFF) { "frame length $total does not fit in 12 bits" }
        val out = ByteArray(total)
        putLe16(out, 0, total or 0x2000)
        putLe16(out, 2, sequence)
        out[4] = OP_SET_PROPERTIES.toByte()
        System.arraycopy(body, 0, out, 5, body.size)
        return out
    }

    /** Convenience: `devEnterMode` as a ready-to-encrypt plaintext frame. */
    fun enterModeFrame(sequence: Int, mode: Int): ByteArray =
        encodeSetPropertiesFrame(sequence, enterMode(mode))

    // ---- encoding --------------------------------------------------------

    /** Encode one property: `piid LE16 | desc(LE16) | value LE`. */
    fun encodeProperty(property: Property): ByteArray {
        val value = valueBytes(property)
        require(value.size <= 0xFFF) { "value length ${value.size} does not fit in 12 bits" }
        val desc = (property.type.code shl 12) or value.size
        val out = ByteArray(4 + value.size)
        putLe16(out, 0, property.piid)
        putLe16(out, 2, desc)
        System.arraycopy(value, 0, out, 4, value.size)
        return out
    }

    /**
     * Encode the op-5 body: `siid u8 | aiid u8 | count u8 | properties...`.
     *
     * `piid` order is preserved as given — it is significant, see the class
     * documentation.
     */
    fun encodeActionBody(siid: Int, aiid: Int, properties: List<Property>): ByteArray {
        require(siid in 1..255) { "siid out of [1,255]" }
        require(aiid in 1..255) { "aiid out of [1,255]" }
        require(properties.size <= 255) { "property count out of [0,255]" }
        require(properties.map { it.piid }.toSet().size == properties.size) {
            "duplicate piid in action entity"
        }
        val parts = properties.map { encodeProperty(it) }
        val total = 3 + parts.sumOf { it.size }
        val out = ByteArray(total)
        out[0] = siid.toByte()
        out[1] = aiid.toByte()
        out[2] = properties.size.toByte()
        var offset = 3
        for (part in parts) {
            System.arraycopy(part, 0, out, offset, part.size)
            offset += part.size
        }
        return out
    }

    /**
     * Encode a complete Spec plaintext frame for an action:
     * `LE16(len|0x2000) LE16(sequence) 0x05 body`.
     *
     * The result is the plaintext of the AES-CCM frame; it is not encrypted
     * here and carries no key material.
     */
    fun encodeActionFrame(sequence: Int, siid: Int, aiid: Int, properties: List<Property>): ByteArray =
        S400SpecProtocol.wrap(sequence, byteArrayOf(OP_ACTION.toByte()) +
            encodeActionBody(siid, aiid, properties))

    /** Convenience: switch-user as a ready-to-encrypt plaintext frame. */
    fun switchUserFrame(sequence: Int, miid: Long, uid: Int, userType: Int): ByteArray =
        encodeActionFrame(sequence, SIID_USER, AIID_USER_SWITCH, switchUser(miid, uid, userType))

    /** Convenience: base-weight as a ready-to-encrypt plaintext frame. */
    fun basicWeightFrame(sequence: Int, miid: Long, uid: Int, userType: Int, weight100g: Int): ByteArray =
        encodeActionFrame(sequence, SIID_USER, AIID_USER_BASIC_WEIGHT,
            basicWeight(miid, uid, userType, weight100g))

    /** Convenience: 13.1 sync as a ready-to-encrypt plaintext frame. */
    fun deviceSyncFrame(
        sequence: Int,
        appVersion: Int,
        unit: Int,
        timestampEpochSeconds: Long,
        isOn: Boolean,
        json: String,
    ): ByteArray = encodeActionFrame(sequence, SIID_DEVICE, AIID_DEVICE_SYNC,
        deviceSync(appVersion, unit, timestampEpochSeconds, isOn, json))

    // ---- internals -------------------------------------------------------

    /** Encode a `WriteProperty` value whose Kotlin type is only known at runtime. */
    private fun rawValueBytes(type: ValueType, value: Any): ByteArray = when (type) {
        ValueType.BOOL -> byteArrayOf(if (value as Boolean) 1 else 0)
        ValueType.UINT8 -> byteArrayOf(((value as Number).toInt() and 0xFF).toByte())
        ValueType.INT8 -> byteArrayOf((value as Number).toInt().toByte())
        ValueType.UINT16 -> le16((value as Number).toInt() and 0xFFFF)
        ValueType.INT16 -> le16((value as Number).toInt() and 0xFFFF)
        ValueType.UINT32 -> le32((value as Number).toLong() and 0xFFFFFFFFL)
        ValueType.INT32 -> le32((value as Number).toLong() and 0xFFFFFFFFL)
        ValueType.UINT64, ValueType.INT64 -> le64((value as Number).toLong())
        ValueType.FLOAT -> le32(java.lang.Float.floatToRawIntBits((value as Number).toFloat()).toLong() and 0xFFFFFFFFL)
        ValueType.STRING -> {
            val bytes = value.toString().toByteArray(Charsets.UTF_8)
            require(bytes.size <= MAX_STRING_BYTES) {
                "string value byte size must be less than $MAX_STRING_BYTES"
            }
            bytes
        }
    }

    private fun valueBytes(property: Property): ByteArray = when (property) {
        is Property.Bool -> byteArrayOf(if (property.value) 1 else 0)
        is Property.UInt8 -> byteArrayOf((property.value and 0xFF).toByte())
        is Property.Int8 -> byteArrayOf(property.value.toByte())
        is Property.UInt16 -> le16(property.value and 0xFFFF)
        is Property.Int16 -> le16(property.value and 0xFFFF)
        is Property.UInt32 -> le32(property.value and 0xFFFFFFFFL)
        is Property.Int32 -> le32(property.value.toLong() and 0xFFFFFFFFL)
        is Property.UInt64 -> le64(property.value)
        is Property.Int64 -> le64(property.value)
        is Property.Float32 -> le32(java.lang.Float.floatToRawIntBits(property.value).toLong() and 0xFFFFFFFFL)
        is Property.Text -> {
            val bytes = property.value.toByteArray(Charsets.UTF_8)
            require(bytes.size <= MAX_STRING_BYTES) {
                "string value byte size must be less than $MAX_STRING_BYTES"
            }
            bytes
        }
    }

    private fun putLe16(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value and 0xFF).toByte()
        out[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    private fun le16(value: Int): ByteArray {
        val out = ByteArray(2)
        putLe16(out, 0, value)
        return out
    }

    private fun le32(value: Long): ByteArray {
        val out = ByteArray(4)
        for (i in 0 until 4) out[i] = ((value ushr (8 * i)) and 0xFF).toByte()
        return out
    }

    private fun le64(value: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) out[i] = ((value ushr (8 * i)) and 0xFF).toByte()
        return out
    }

    private fun md5Hex(bytes: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("MD5").digest(bytes)
        val hex = CharArray(digest.size * 2)
        val digits = "0123456789abcdef"
        for (i in digest.indices) {
            val b = digest[i].toInt() and 0xFF
            hex[i * 2] = digits[b ushr 4]
            hex[i * 2 + 1] = digits[b and 0x0F]
        }
        return String(hex)
    }
}
