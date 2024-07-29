#ifndef PCAP_TEST_H
# include "pcap-test.h"
#endif

void endian_switch(void *data_ptr, size_t size) {
	BYTE *tmp = (BYTE *)malloc(size * sizeof(BYTE));
	for (size_t i = 0; i < size; i++) tmp[i] = ((BYTE*)data_ptr)[size-i];
	memcpy(data_ptr, tmp, size);
	safe_free(tmp, size);
}

void safe_free(void *ptr, size_t size) {
	memset(ptr, 0, size);
	free(ptr);
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}