/*
 * ChaCha20 keystream XOR for the ESP32-P4 v3.x HP core (RV32 with Zbb).
 * chacha20() calls it when crypto_esp32p4_zb is set; see crypto.h.
 *
 * void chacha20_blocks_esp32p4(uint32_t state[16], uint8_t *out,
 *                              const uint8_t *in, uint32_t nblocks);
 *
 * Encrypts nblocks whole 64-byte blocks: out = in ^ keystream, and advances the
 * block counter in state[12]. in and out must be 4-byte aligned; they may be
 * the same buffer. The sixteen state words stay in registers through the
 * twenty rounds, each rotate is one Zbb rori, and each keystream word (the
 * working state plus the input state) is XORed into the data straight from
 * its register.
 *
 * Register use: a0 state, a1 out, a2 in, a3 blocks left, a4 round counter,
 * a5..a7 and t0..t2 scratch, working state in s0..s11 and t3..t6.
 */
    .section .text.chacha20_blocks_esp32p4, "ax"
    .option push
    .option arch, +zbb
    .balign 4
    .global chacha20_blocks_esp32p4
    .type chacha20_blocks_esp32p4, @function
chacha20_blocks_esp32p4:
    beqz    a3, 9f
    addi    sp, sp, -48
    sw      s0, 0(sp)
    sw      s1, 4(sp)
    sw      s2, 8(sp)
    sw      s3, 12(sp)
    sw      s4, 16(sp)
    sw      s5, 20(sp)
    sw      s6, 24(sp)
    sw      s7, 28(sp)
    sw      s8, 32(sp)
    sw      s9, 36(sp)
    sw      s10, 40(sp)
    sw      s11, 44(sp)
1:
    lw      s0, 0(a0)
    lw      s1, 4(a0)
    lw      s2, 8(a0)
    lw      s3, 12(a0)
    lw      s4, 16(a0)
    lw      s5, 20(a0)
    lw      s6, 24(a0)
    lw      s7, 28(a0)
    lw      s8, 32(a0)
    lw      s9, 36(a0)
    lw      s10, 40(a0)
    lw      s11, 44(a0)
    lw      t3, 48(a0)
    lw      t4, 52(a0)
    lw      t5, 56(a0)
    lw      t6, 60(a0)
    li      a4, 10
2:
    /* column rounds */
    add     s0, s0, s4
    add     s1, s1, s5
    add     s2, s2, s6
    add     s3, s3, s7
    xor     t3, t3, s0
    xor     t4, t4, s1
    xor     t5, t5, s2
    xor     t6, t6, s3
    rori    t3, t3, 16
    rori    t4, t4, 16
    rori    t5, t5, 16
    rori    t6, t6, 16
    add     s8, s8, t3
    add     s9, s9, t4
    add     s10, s10, t5
    add     s11, s11, t6
    xor     s4, s4, s8
    xor     s5, s5, s9
    xor     s6, s6, s10
    xor     s7, s7, s11
    rori    s4, s4, 20
    rori    s5, s5, 20
    rori    s6, s6, 20
    rori    s7, s7, 20
    add     s0, s0, s4
    add     s1, s1, s5
    add     s2, s2, s6
    add     s3, s3, s7
    xor     t3, t3, s0
    xor     t4, t4, s1
    xor     t5, t5, s2
    xor     t6, t6, s3
    rori    t3, t3, 24
    rori    t4, t4, 24
    rori    t5, t5, 24
    rori    t6, t6, 24
    add     s8, s8, t3
    add     s9, s9, t4
    add     s10, s10, t5
    add     s11, s11, t6
    xor     s4, s4, s8
    xor     s5, s5, s9
    xor     s6, s6, s10
    xor     s7, s7, s11
    rori    s4, s4, 25
    rori    s5, s5, 25
    rori    s6, s6, 25
    rori    s7, s7, 25
    /* diagonal rounds */
    add     s0, s0, s5
    add     s1, s1, s6
    add     s2, s2, s7
    add     s3, s3, s4
    xor     t6, t6, s0
    xor     t3, t3, s1
    xor     t4, t4, s2
    xor     t5, t5, s3
    rori    t6, t6, 16
    rori    t3, t3, 16
    rori    t4, t4, 16
    rori    t5, t5, 16
    add     s10, s10, t6
    add     s11, s11, t3
    add     s8, s8, t4
    add     s9, s9, t5
    xor     s5, s5, s10
    xor     s6, s6, s11
    xor     s7, s7, s8
    xor     s4, s4, s9
    rori    s5, s5, 20
    rori    s6, s6, 20
    rori    s7, s7, 20
    rori    s4, s4, 20
    add     s0, s0, s5
    add     s1, s1, s6
    add     s2, s2, s7
    add     s3, s3, s4
    xor     t6, t6, s0
    xor     t3, t3, s1
    xor     t4, t4, s2
    xor     t5, t5, s3
    rori    t6, t6, 24
    rori    t3, t3, 24
    rori    t4, t4, 24
    rori    t5, t5, 24
    add     s10, s10, t6
    add     s11, s11, t3
    add     s8, s8, t4
    add     s9, s9, t5
    xor     s5, s5, s10
    xor     s6, s6, s11
    xor     s7, s7, s8
    xor     s4, s4, s9
    rori    s5, s5, 25
    rori    s6, s6, 25
    rori    s7, s7, 25
    rori    s4, s4, 25
    addi    a4, a4, -1
    bnez    a4, 2b
    /* keystream = working state + input state; out = in ^ keystream */
    lw      a5, 0(a0)
    lw      a7, 4(a0)
    lw      t1, 8(a0)
    lw      a6, 0(a2)
    lw      t0, 4(a2)
    lw      t2, 8(a2)
    add     s0, s0, a5
    add     s1, s1, a7
    add     s2, s2, t1
    xor     s0, s0, a6
    xor     s1, s1, t0
    xor     s2, s2, t2
    sw      s0, 0(a1)
    sw      s1, 4(a1)
    sw      s2, 8(a1)
    lw      a5, 12(a0)
    lw      a7, 16(a0)
    lw      t1, 20(a0)
    lw      a6, 12(a2)
    lw      t0, 16(a2)
    lw      t2, 20(a2)
    add     s3, s3, a5
    add     s4, s4, a7
    add     s5, s5, t1
    xor     s3, s3, a6
    xor     s4, s4, t0
    xor     s5, s5, t2
    sw      s3, 12(a1)
    sw      s4, 16(a1)
    sw      s5, 20(a1)
    lw      a5, 24(a0)
    lw      a7, 28(a0)
    lw      t1, 32(a0)
    lw      a6, 24(a2)
    lw      t0, 28(a2)
    lw      t2, 32(a2)
    add     s6, s6, a5
    add     s7, s7, a7
    add     s8, s8, t1
    xor     s6, s6, a6
    xor     s7, s7, t0
    xor     s8, s8, t2
    sw      s6, 24(a1)
    sw      s7, 28(a1)
    sw      s8, 32(a1)
    lw      a5, 36(a0)
    lw      a7, 40(a0)
    lw      t1, 44(a0)
    lw      a6, 36(a2)
    lw      t0, 40(a2)
    lw      t2, 44(a2)
    add     s9, s9, a5
    add     s10, s10, a7
    add     s11, s11, t1
    xor     s9, s9, a6
    xor     s10, s10, t0
    xor     s11, s11, t2
    sw      s9, 36(a1)
    sw      s10, 40(a1)
    sw      s11, 44(a1)
    lw      a5, 48(a0)
    lw      a7, 52(a0)
    lw      t1, 56(a0)
    lw      a6, 48(a2)
    lw      t0, 52(a2)
    lw      t2, 56(a2)
    add     t3, t3, a5
    add     t4, t4, a7
    add     t5, t5, t1
    xor     t3, t3, a6
    xor     t4, t4, t0
    xor     t5, t5, t2
    sw      t3, 48(a1)
    sw      t4, 52(a1)
    sw      t5, 56(a1)
    lw      a5, 60(a0)
    lw      a6, 60(a2)
    add     t6, t6, a5
    xor     t6, t6, a6
    sw      t6, 60(a1)
    lw      a5, 48(a0)
    addi    a1, a1, 64
    addi    a2, a2, 64
    addi    a5, a5, 1
    addi    a3, a3, -1
    sw      a5, 48(a0)
    bnez    a3, 1b
    lw      s0, 0(sp)
    lw      s1, 4(sp)
    lw      s2, 8(sp)
    lw      s3, 12(sp)
    lw      s4, 16(sp)
    lw      s5, 20(sp)
    lw      s6, 24(sp)
    lw      s7, 28(sp)
    lw      s8, 32(sp)
    lw      s9, 36(sp)
    lw      s10, 40(sp)
    lw      s11, 44(sp)
    addi    sp, sp, 48
9:  ret
    .size chacha20_blocks_esp32p4, .-chacha20_blocks_esp32p4
    .option pop
