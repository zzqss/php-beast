
/*
 * You can modify this sign to disguise your encrypt file
 */
char encrypt_file_header_sign[] = {
	0x3c, 0x17, 0xa5, 0x0b,
	0xf7, 0xb3, 0x5e, 0xea
};

int encrypt_file_header_length = sizeof(encrypt_file_header_sign);
