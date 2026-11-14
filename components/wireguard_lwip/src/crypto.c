#include "crypto.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef CRYPTO_ESP32P4_ZB
#include "hal/efuse_hal.h"

bool crypto_esp32p4_zb;

__attribute__((constructor)) static void crypto_detect_esp32p4_zb(void) {
	crypto_esp32p4_zb = efuse_hal_chip_revision() >= 302;
}
#endif

void crypto_zero(void *dest, size_t len) {
	// memset runs a word at a time; the empty asm that takes dest and clobbers
	// memory stops the compiler from dropping the stores as dead.
	memset(dest, 0, len);
	__asm__ __volatile__("" : : "r"(dest) : "memory");
}

bool crypto_equal(const void *a, const void *b, size_t size) {
	uint8_t neq = 0;
	while (size > 0) {
		neq |= *(uint8_t *)a ^ *(uint8_t *)b;
		a += 1;
		b += 1;
		size -= 1;
	}
	return (neq) ? false : true;
}
