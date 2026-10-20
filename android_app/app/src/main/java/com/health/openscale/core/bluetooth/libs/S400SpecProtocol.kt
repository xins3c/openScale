/*
 * openScale — GPL-3.0-or-later
 */
package com.health.openscale.core.bluetooth.libs

/** Minimal authenticated MIoT Spec envelope observed in S400 0x001B notifications.
 * This class never handles the device token or AES key. Call only after AES-CCM succeeds.
 */
object S400SpecProtocol {
    private const val MAX_BODY = 512
    private const val HEADER_LENGTH = 4
    private const val RESULT_PREFIX_LENGTH = 9
    private val EVENT_RESULT = byteArrayOf(8, 2)

    /** Captured session bootstrap: a 5-byte command echoed verbatim by the device.
     * The trailing F0 is a protocol control code, not a subscription to event 8.2.
     */
    fun bootstrap(sequence: Int = 0): ByteArray = wrap(sequence, byteArrayOf(0xf0.toByte()))

    /** A proprietary 4-byte Spec length/sequence envelope. Payload is binary, not JSON. */
    fun wrap(sequence: Int, body: ByteArray): ByteArray {
        require(sequence in 0..0xffff)
        require(body.size + HEADER_LENGTH <= MAX_BODY)
        val len = body.size + HEADER_LENGTH
        return byteArrayOf(len.toByte(), (0x20 or (len ushr 8)).toByte(),
            sequence.toByte(), (sequence ushr 8).toByte()) + body
    }

    /** Returns only the firmware's 32-field CSV from a FINAL event.8.2 packet.
     * Verified against the first and third authenticated HCI sessions. All other
     * messages (8.1/live weight, action replies, bootstrap) are ignored.
     */
    fun finalResultCsv(plaintext: ByteArray): ByteArray? {
        if (plaintext.size !in HEADER_LENGTH + RESULT_PREFIX_LENGTH + 40..MAX_BODY) return null
        val encodedLength = (plaintext[0].toInt() and 0xff) or
            ((plaintext[1].toInt() and 0x1f) shl 8)
        if (encodedLength != plaintext.size || (plaintext[1].toInt() and 0xe0) != 0x20) return null
        val body = plaintext.copyOfRange(HEADER_LENGTH, plaintext.size)
        if (body.size < RESULT_PREFIX_LENGTH || body[1] != EVENT_RESULT[0] || body[2] != EVENT_RESULT[1]) return null
        val csv = body.copyOfRange(RESULT_PREFIX_LENGTH, body.size)
        if (csv.count { it == ','.code.toByte() } != 31) return null
        return csv
    }
}
