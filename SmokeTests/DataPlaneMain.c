#include "hajimi_dataplane.h"
#include <stdio.h>

int main(void) {
    const int code = hajimi_dataplane_self_test();
    if (code != 0) {
        fprintf(stderr, "C11 data-plane self-test failed at vector %d\n", code);
        return 1;
    }
    puts("C11 zero-copy IPv4/IPv6/TCP/UDP data-plane & checksum self-test passed");
    return 0;
}
