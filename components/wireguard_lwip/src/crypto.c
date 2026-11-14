#include "crypto.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef CRYPTO_ESP32P4_ZB
#include "hal/efuse_hal.h"

bool crypto_esp32p4_zb;

__attribute__((constructor)) static void crypto_detect_esp32p4_zb(void) {
	crypto_esp32p4_zb = efuse_hal_chip_revision() >= 302;
}
#endif

void crypto_zero(void *dest, size_t len) {
	volatile uint8_t *p = (uint8_t *)dest;
	while (len--) {
		*p++ = 0;
	}
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
