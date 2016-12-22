#include "sysInclude.h"
#include <cstdlib>
#include <cstring>

extern void ip_DiscardPkt(char* pBuffer, int type);
extern void ip_SendtoLower(char* pBuffer, int length);
extern void ip_SendtoUp(char* pBuffer, int length);
extern unsigned int getIpv4Address();

#ifndef byte
#define byte unsigned char
#endif


/* Handle packets received */
int stud_ip_recv(char* pBuffer, unsigned short length) {
	const unsigned int Version = (unsigned)pBuffer[0] >> 4;
	const unsigned int IHL = (unsigned)pBuffer[0] & 0xF;
	const unsigned int TTL = (unsigned)pBuffer[8];
	const unsigned int DstAddr = ntohl(*(unsigned int *)(&pBuffer[16]));
	unsigned int HeaderCheckSum = 0;

	if (Version != 4) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
		return -1;
	}
	if (IHL < 5) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
		return -11;
	}
	if (!TTL) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
		return -1;
	}

	if (DstAddr != getIpv4Address() && DstAddr != 0xFFFFFFFF) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
		return -1;
	}

	for (int i = 0; i < 20; i += 2) {
		HeaderCheckSum += ((pBuffer[i] & 0xFF) << 8) + (pBuffer[i + 1] & 0xFF);
	}
	HeaderCheckSum += (HeaderCheckSum >> 16);

	if ((unsigned short)(~HeaderCheckSum)) {
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
		return -1;
	}

	ip_SendtoUp(pBuffer, length);

	return 0;
}

/* Send packets */
int stud_ip_Upsend(char* pBuffer, unsigned short len, unsigned int srcAddr,
                   unsigned int dstAddr, byte protocol, byte ttl) {
	const unsigned int Version = 4;
	const unsigned int IHL = 5;
	const unsigned int TotalLen = 4 * IHL + len;
	unsigned int HeaderCheckSum = 0;
	unsigned char* Buffer = (unsigned char*) malloc(TotalLen);

	memset(Buffer, 0, TotalLen);

	Buffer[0] = Version << 4 | IHL;
	Buffer[2] = TotalLen >> 8;
	Buffer[3] = TotalLen;
	Buffer[8] = ttl;
	Buffer[9] = protocol;
	Buffer[12] = srcAddr >> 24;
	Buffer[13] = srcAddr >> 16;
	Buffer[14] = srcAddr >> 8;
	Buffer[15] = srcAddr;
	Buffer[16] = dstAddr >> 24;
	Buffer[17] = dstAddr >> 16;
	Buffer[18] = dstAddr >> 8;
	Buffer[19] = dstAddr;
	memcpy(Buffer + 20, pBuffer, len);
	for (int i = 0; i < 20; i += 2) {
		HeaderCheckSum += ((Buffer[i] & 0xFF) << 8) + (Buffer[i + 1] & 0xFF);
	}
	HeaderCheckSum += HeaderCheckSum >> 16;
	HeaderCheckSum = ~HeaderCheckSum;
	Buffer[10] = (char)((unsigned short)HeaderCheckSum >> 8);
	Buffer[11] = (char)((unsigned short)HeaderCheckSum & 0xFF);

	ip_SendtoLower((char*)Buffer, TotalLen);

	return 0;
}