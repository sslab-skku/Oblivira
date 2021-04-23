
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "sgx_trts.h"

#include "Enclave.h"
// #include "Enclave_t.h" /* print_string */

#define ADD_ENTROPY_SIZE 32

extern "C" {
void ecall_start_tls_server(void) {}
}
