package com.health.openscale.core.bluetooth.libs

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class S400SpecMeasurementTest {
    // Fully synthetic values. No device IDs, keys, or real health data.
    private val fields = arrayOf(
        "1000000001", "1", "1", "700", "65", "0", "1700000000", "200", "550",
        "600", "30", "8", "155", "350", "240", "700", "-20", "-30", "-40",
        "10", "1600", "4", "28", "70", "650", "40", "140", "560", "420",
        "105", "5000", "4500"
    )

    private fun parse(): S400SpecMeasurement? = S400SpecMeasurement.parse(fields.joinToString(",").toByteArray())

    @Test fun parsesAndScalesDeviceFields() {
        val value = parse()
        assertThat(value).isNotNull()
        assertThat(value!!.weightKg).isEqualTo(70f)
        assertThat(value.bodyFatPercent).isEqualTo(20f)
        assertThat(value.boneMassKg).isEqualTo(3f)
        assertThat(value.skeletalMuscleKg).isEqualTo(35f)
        assertThat(value.bodyWaterPercent).isEqualTo(60f)
        assertThat(value.visceralFatLevel).isEqualTo(8)
        assertThat(value.bmrKcal).isEqualTo(1600)
        assertThat(value.impedanceHighOhm).isEqualTo(500f)
        assertThat(value.impedanceLowOhm).isEqualTo(450f)
        assertThat(value.musclePercent).isEqualTo(65f)
        assertThat(value.hasComposition).isTrue()
    }

    @Test fun missingImpedanceMeansNoComposition() {
        fields[30] = "0"
        assertThat(parse()!!.hasComposition).isFalse()
        fields[30] = "5000"; fields[31] = "0"
        assertThat(parse()!!.hasComposition).isFalse()
    }

    @Test fun absentMusclePercentIsNullNotZero() {
        fields[24] = "0"
        assertThat(parse()!!.musclePercent).isNull()
    }

    @Test fun rejectsMusclePercentAboveOneHundred() {
        fields[24] = "1500"
        assertThat(parse()).isNull()
    }

    @Test fun rejectsTruncatedOrNonNumeric() {
        assertThat(S400SpecMeasurement.parse("1,2,3".toByteArray())).isNull()
        fields[7] = "bad"
        assertThat(parse()).isNull()
    }

    @Test fun rejectsOutOfRange() {
        fields[3] = "9000"
        assertThat(parse()).isNull()
    }
}
