#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes.h"
// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1


//AES/CBC/PKCS5Padding
/*****************************************************************************/
//key为秘钥，iv为分组向量，增加破解难度
uint8_t key[] = { 0x6e,0x6e,0x2a,0x5e,0x33,0x56,0x56,0x53,0x70,0x52,0x4d,0x53,0x76,0x41,0x4c,0x78 };
uint8_t iv[] = { 0x43,0x4b,0x67,0x33,0x6a,0x6d,0x5e,0x18,0x42,0x78,0x36,0x23,0x33,0x78,0x65,0x38 };

int main(void)
{
	char* msg = "待加密的明文";
	int len = strlen(msg);
	printf("len of data:%d\n",len);
	int lenPadding = len % 16 == 0?0:16 - len % 16;
	printf("lenPadding:%d\n",lenPadding);
	uint8_t* input = new uint8_t[len+lenPadding];
	for(int i=0;i<len;i++){
		input[i] = (uint8_t)msg[i];
	}
	for(int i=len;i<len+lenPadding;i++){
		input[i] = (uint8_t)'#'; // #号填充
	}
	//加密后的字节数组
	uint8_t* encoderData = new uint8_t[len+lenPadding];
	AES128_CBC_encrypt_buffer(encoderData, input, len+lenPadding, key, iv); //加密过程
	printf("encrypt ok\n");

	//uint8_t in[] = { 0x9f,0x3a,0xbd,0x40,0x5a,0x9d,0xfe,0x72,0x20,0x89,0x3c,0x45,0xa7,0x58,0xe8,0xa5,0x2a,0x5b,0x2a,0xdb,0x9a,0xcd,0xa5,0x16,0x13,0xf2,0xc0,0x9d,0x8d,0xa0,0xcb,0xf9 };

	uint8_t bufferByte[10000];
	len = len + lenPadding;
	AES128_CBC_decrypt_buffer(bufferByte, encoderData, len, key, iv);
	char str[100];

	for (int i = 0; i <len; i++) {
		str[i] = (char)bufferByte[i];
		//printf("%c",bufferByte[i]);
	}
	str[len] = '\0';
	printf("%s\n", str);
    return 0;
}
