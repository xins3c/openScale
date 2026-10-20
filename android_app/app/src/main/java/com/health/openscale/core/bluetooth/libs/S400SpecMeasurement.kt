/*
 * openScale
 * Copyright (C) 2025 olie.xdev <olie.xdeveloper@googlemail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.health.openscale.core.bluetooth.libs

/** A final, device-computed 8.2 composition result, not an impedance estimate. */
data class S400SpecMeasurement(
    val deviceUserId: Int,
    val weightKg: Float,
    val heartRate: Int?,
    val status: Int,
    val timeSeconds: Long,
    val bodyFatPercent: Float,
    val softLeanMassKg: Float,
    val bodyWaterPercent: Float,
    val boneMassKg: Float,
    val visceralFatLevel: Int,
    val proteinPercent: Float,
    val skeletalMuscleKg: Float,
    val bmi: Float,
    val bmrKcal: Int,
    val metabolicAge: Int,
    val fatFreeMassKg: Float,
    val bodyWaterMassKg: Float,
    val proteinMassKg: Float,
    val impedanceHighOhm: Float,
    val impedanceLowOhm: Float,
    /**
     * Validated `miid` (field 0). Retained only so the handler can prove the result belongs to
     * the identity it switched the scale to; it is never logged or exported on its own.
     */
    val miid: Long = 0L,
    /** Validated `userType` (field 2), same purpose as [miid]. */
    val userType: Int = -1,
) {
    companion object {
        /**
         * The 32 CSV positions are from Xiaomi Home's `event.8.2` handler
         * (Metro module 10466) and the /10 unit conversions in module 10040.
         * Only call this after channel reassembly and authenticated AES-CCM.
         * Never include rejected payload text in an exception/log.
         */
        fun parse(payload: ByteArray): S400SpecMeasurement? {
            if (payload.size !in 40..512) return null
            // Strict printable numeric CSV prevents JSON/control data and large
            // attacker-supplied strings from reaching the measurement store.
            if (payload.any { b ->
                    val c = b.toInt() and 0xff
                    c != 44 && c != 45 && c !in 48..57
                }) return null
            val fields = payload.toString(Charsets.US_ASCII).split(',')
            if (fields.size != 32 || fields.any { it.isEmpty() || it.length > 20 }) return null
            fun integer(i: Int): Int? = fields[i].toIntOrNull()
            fun tenth(i: Int): Float? = integer(i)?.div(10f)
            // miid can exceed signed 32-bit and is validated (and retained) as a Long so the
            // handler can match the result to the identity the scale was switched to.
            val miid = fields[0].toLongOrNull() ?: return null
            val user = integer(1) ?: return null
            val userType = integer(2) ?: return null
            val status = integer(5) ?: return null
            val time = fields[6].toLongOrNull() ?: return null
            val weight = tenth(3) ?: return null
            val heart = integer(4) ?: return null
            val bfp = tenth(7) ?: return null
            val slm = tenth(8) ?: return null
            val water = tenth(9) ?: return null
            val bone = tenth(10) ?: return null
            val visceral = integer(11) ?: return null
            val protein = tenth(12) ?: return null
            val muscle = tenth(13) ?: return null
            val bmi = tenth(14) ?: return null
            val bmr = integer(20) ?: return null
            val age = integer(22) ?: return null
            val ffm = tenth(27) ?: return null
            val waterMass = tenth(28) ?: return null
            val proteinMass = tenth(29) ?: return null
            val high = tenth(30) ?: return null
            val low = tenth(31) ?: return null
            if (user < 0 || userType !in 0..3 || time <= 0 || weight !in 2f..350f ||
                heart !in 0..250 || bfp !in 0f..100f ||
                water !in 0f..100f || protein !in 0f..100f ||
                bone < 0 || slm < 0 || muscle < 0 || ffm < 0 ||
                visceral !in 0..100 || bmr !in 0..10000 || age !in 0..150 ||
                high < 0 || low < 0 || bmi !in 0f..150f) return null
            return S400SpecMeasurement(
                user, weight, heart.takeIf { it > 0 }, status, time, bfp,
                slm, water, bone, visceral, protein, muscle, bmi,
                bmr, age, ffm, waterMass, proteinMass, high, low,
                miid, userType,
            )
        }
    }
}
