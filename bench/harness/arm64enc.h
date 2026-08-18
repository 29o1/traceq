#pragma once
// Minimal ARM64 encoder used only to build realistic instruction streams for
// the benchmark corpus. Every word here is a real AArch64 encoding; the site
// compiler disassembles them with Capstone, which round-trip checks the
// encoders in selftest.
#include <cstdint>
#include <cassert>

namespace gt {
namespace enc {

constexpr uint32_t XZ = 31;

inline uint32_t movz(int rd, uint16_t imm, int hw = 0) {
    return 0xD2800000u | (hw << 21) | (uint32_t(imm) << 5) | rd;
}
inline uint32_t movk(int rd, uint16_t imm, int hw = 0) {
    return 0xF2800000u | (hw << 21) | (uint32_t(imm) << 5) | rd;
}
inline uint32_t mov_reg(int rd, int rm) { // orr xd, xzr, xm
    return 0xAA0003E0u | (rm << 16) | rd;
}
inline uint32_t add_imm(int rd, int rn, uint16_t imm12) {
    return 0x91000000u | (uint32_t(imm12) << 10) | (rn << 5) | rd;
}
inline uint32_t sub_imm(int rd, int rn, uint16_t imm12) {
    return 0xD1000000u | (uint32_t(imm12) << 10) | (rn << 5) | rd;
}
inline uint32_t add_reg(int rd, int rn, int rm) {
    return 0x8B000000u | (rm << 16) | (rn << 5) | rd;
}
inline uint32_t eor_reg(int rd, int rn, int rm) {
    return 0xCA000000u | (rm << 16) | (rn << 5) | rd;
}
inline uint32_t eor_w(int rd, int rn, int rm) {
    return 0x4A000000u | (rm << 16) | (rn << 5) | rd;
}
inline uint32_t and_reg(int rd, int rn, int rm) {
    return 0x92000000u | (rm << 16) | (rn << 5) | rd;
}
inline uint32_t cmp_imm(int rn, uint16_t imm12) { // subs xzr, xn, #imm
    return 0xF1000000u | (uint32_t(imm12) << 10) | (rn << 5) | XZ;
}
inline uint32_t cmp_reg(int rn, int rm) { // subs xzr, xn, xm
    return 0xEB000000u | (rm << 16) | (rn << 5) | XZ;
}
inline uint32_t subs_reg(int rd, int rn, int rm) { // flag-setting subtract, keeps result
    return 0xEB000000u | (rm << 16) | (rn << 5) | rd;
}
// conds: 0=eq 1=ne ...
inline uint32_t csel(int rd, int rn, int rm, int cond) {
    return 0x9A800000u | (rm << 16) | (cond << 12) | (rn << 5) | rd;
}
inline uint32_t eor_v16b(int rd, int rn, int rm) { // eor vd.16b, vn.16b, vm.16b
    return 0x6E201C00u | (rm << 16) | (rn << 5) | rd;
}
inline uint32_t str_q(int rt, int rn, uint32_t off_bytes) { // off % 16 == 0
    assert(off_bytes % 16 == 0 && off_bytes < (1u << 16));
    return 0x3D800000u | ((off_bytes / 16) << 10) | (rn << 5) | rt;
}
inline uint32_t ldr_q(int rt, int rn, uint32_t off_bytes) {
    assert(off_bytes % 16 == 0 && off_bytes < (1u << 16));
    return 0x3DC00000u | ((off_bytes / 16) << 10) | (rn << 5) | rt;
}
inline uint32_t ldr_x(int rt, int rn, uint32_t off_bytes) { // off % 8 == 0
    assert(off_bytes % 8 == 0 && off_bytes < (1u << 15));
    return 0xF9400000u | ((off_bytes / 8) << 10) | (rn << 5) | rt;
}
inline uint32_t str_x(int rt, int rn, uint32_t off_bytes) {
    assert(off_bytes % 8 == 0 && off_bytes < (1u << 15));
    return 0xF9000000u | ((off_bytes / 8) << 10) | (rn << 5) | rt;
}
inline uint32_t ldr_w(int rt, int rn, uint32_t off_bytes) {
    assert(off_bytes % 4 == 0 && off_bytes < (1u << 12));
    return 0xB9400000u | ((off_bytes / 4) << 10) | (rn << 5) | rt;
}
inline uint32_t str_w(int rt, int rn, uint32_t off_bytes) {
    assert(off_bytes % 4 == 0 && off_bytes < (1u << 12));
    return 0xB9000000u | ((off_bytes / 4) << 10) | (rn << 5) | rt;
}
inline uint32_t ldrb(int rt, int rn, uint32_t off_bytes) {
    assert(off_bytes < (1u << 12));
    return 0x39400000u | (off_bytes << 10) | (rn << 5) | rt;
}
inline uint32_t strb(int rt, int rn, uint32_t off_bytes) {
    assert(off_bytes < (1u << 12));
    return 0x39000000u | (off_bytes << 10) | (rn << 5) | rt;
}
inline uint32_t b(int64_t off_bytes) {
    assert(off_bytes % 4 == 0);
    return 0x14000000u | (uint32_t((off_bytes / 4) & 0x3FFFFFF) & 0x3FFFFFFu);
}
inline uint32_t bl(int64_t off_bytes) {
    assert(off_bytes % 4 == 0);
    return 0x94000000u | (uint32_t((off_bytes / 4) & 0x3FFFFFF) & 0x3FFFFFFu);
}
// conds: 0=eq 1=ne ...
inline uint32_t bcond(int cond, int64_t off_bytes) {
    assert(off_bytes % 4 == 0);
    return 0x54000000u | (uint32_t((off_bytes / 4) & 0x7FFFF) << 5) | cond;
}
inline uint32_t br(int rn)  { return 0xD61F0000u | (rn << 5); }
inline uint32_t blr(int rn) { return 0xD63F0000u | (rn << 5); }
inline uint32_t ret()       { return 0xD65F03C0u; }
inline uint32_t nop()       { return 0xD503201Fu; }
inline uint32_t svc(uint16_t num) { return 0xD4000001u | (uint32_t(num) << 5); }
inline uint32_t stp_x29_push() { return 0xA9BF7BFDu; } // stp x29,x30,[sp,#-16]!
inline uint32_t ldp_x29_pop()  { return 0xA8C17BFDu; } // ldp x29,x30,[sp],#16

} // namespace enc
} // namespace gt
