package com.health.openscale.core.bluetooth.libs

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class S400SpecProtocolTest {
    private val csv = (listOf("9876543210", "1", "1", "873", "78", "0", "1792037139") +
        List(25) { "123" }).joinToString(",").toByteArray(Charsets.US_ASCII)

    @Test fun bootstrapRoundTrip() {
        val frame = S400SpecProtocol.bootstrap()
        assertThat(frame).isEqualTo(byteArrayOf(5, 0x20, 0, 0, 0xf0.toByte()))
    }

    @Test fun stripsVerifiedEventEnvelope() {
        val body = byteArrayOf(0x42, 8, 2, 0, 0, 0, 0, 0, 0) + csv
        val frame = S400SpecProtocol.wrap(123, body)
        assertThat(S400SpecProtocol.finalResultCsv(frame)).isEqualTo(csv)
    }

    @Test fun rejectsOtherEventBadLengthAndNonCsv() {
        val body = byteArrayOf(0x42, 8, 1, 0, 0, 0, 0, 0, 0) + csv
        assertThat(S400SpecProtocol.finalResultCsv(S400SpecProtocol.wrap(123, body))).isNull()
        val result = S400SpecProtocol.wrap(123, byteArrayOf(0x42, 8, 2, 0, 0, 0, 0, 0, 0) + csv)
        result[0] = 0
        assertThat(S400SpecProtocol.finalResultCsv(result)).isNull()
        assertThat(S400SpecProtocol.finalResultCsv(S400SpecProtocol.wrap(123, byteArrayOf(0x42, 8, 2)))).isNull()
    }
}
