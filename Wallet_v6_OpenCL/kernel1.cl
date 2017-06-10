// kernel1.cl
#define PASS_LEN 5
#define ALPHA_LEN 62
#pragma OPENCL EXTENSION cl_amd_printf:enable

#define WALLET_CRYPTO_SALT_SIZE 8
#define WALLET_CRYPTO_KEY_SIZE 32
#define DIGEST_SIZE 64
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_F1(x) (SHA2_ROTR(x, 28) ^ SHA2_ROTR(x, 34) ^ SHA2_ROTR(x, 39))
#define SHA512_F2(x) (SHA2_ROTR(x, 14) ^ SHA2_ROTR(x, 18) ^ SHA2_ROTR(x, 41))
#define SHA512_F3(x) (SHA2_ROTR(x,  1) ^ SHA2_ROTR(x,  8) ^ SHA2_SHFR(x,  7))
#define SHA512_F4(x) (SHA2_ROTR(x, 19) ^ SHA2_ROTR(x, 61) ^ SHA2_SHFR(x,  6))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (unsigned char) ((x)      );       \
    *((str) + 2) = (unsigned char) ((x) >>  8);       \
    *((str) + 1) = (unsigned char) ((x) >> 16);       \
    *((str) + 0) = (unsigned char) ((x) >> 24);       \
}
#define SHA2_UNPACK64(x, str)                 \
{                                             \
    *((str) + 7) = (unsigned char) ((x)      );       \
    *((str) + 6) = (unsigned char) ((x) >>  8);       \
    *((str) + 5) = (unsigned char) ((x) >> 16);       \
    *((str) + 4) = (unsigned char) ((x) >> 24);       \
    *((str) + 3) = (unsigned char) ((x) >> 32);       \
    *((str) + 2) = (unsigned char) ((x) >> 40);       \
    *((str) + 1) = (unsigned char) ((x) >> 48);       \
    *((str) + 0) = (unsigned char) ((x) >> 56);       \
}
#define SHA2_PACK64(str, x)                   \
{                                             \
    *(x) =   ((unsigned long) *((str) + 7)      )    \
           | ((unsigned long) *((str) + 6) <<  8)    \
           | ((unsigned long) *((str) + 5) << 16)    \
           | ((unsigned long) *((str) + 4) << 24)    \
           | ((unsigned long) *((str) + 3) << 32)    \
           | ((unsigned long) *((str) + 2) << 40)    \
           | ((unsigned long) *((str) + 1) << 48)    \
           | ((unsigned long) *((str) + 0) << 56);   \
}
// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
// Multiplty is a macro used to multiply numbers in the field GF(2^8)
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))
#define Nb 4
// The number of rounds in AES Cipher. It is simply initiated to zero. The actual value is recieved in the program.
#define Nr 14
// The number of 32 bit words in the key. It is simply initiated to zero. The actual value is recieved in the program.
#define Nk 8


void SHA512_transform( unsigned char *message, unsigned int block_nb,
	unsigned long *md_data,  unsigned long *sha512_k)
{
	unsigned long w[80];
	unsigned long wv[8];
	unsigned long t1, t2;
	 unsigned char *sub_block;
	int i, j;
	for (i = 0; i < (int)block_nb; i++) {
		sub_block = message + (i << 7);
		for (j = 0; j < 16; j++) {
			SHA2_PACK64(&sub_block[j << 3], &w[j]);
		}
		for (j = 16; j < 80; j++) {
			w[j] = SHA512_F4(w[j - 2]) + w[j - 7] + SHA512_F3(w[j - 15]) + w[j - 16];
		}
		for (j = 0; j < 8; j++) {
			wv[j] = md_data[j];
		}
		for (j = 0; j < 80; j++) {
			t1 = wv[7] + SHA512_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
				+ sha512_k[j] + w[j];
			t2 = SHA512_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}
		for (j = 0; j < 8; j++) {
			md_data[j] += wv[j];
		}

	}
}

void SHA512_update( unsigned char *message, unsigned int len, unsigned long *md_data,
	unsigned char *m_block, unsigned int *m_tot_len, unsigned int *m_len,  unsigned long *sha512_k)
{
	unsigned int block_nb, i;
	unsigned int new_len, rem_len, tmp_len;
	 unsigned char *shifted_message;
	tmp_len = 128 - (*m_len);
	rem_len = len < tmp_len ? len : tmp_len;
	//memcpy(&m_block[m_len], message, rem_len);
	for (i = 0; i < rem_len; ++i)
		m_block[(*m_len) + i] = message[i];

	if ((*m_len) + len < 128) {
		(*m_len) += len;
		return;
	}
	new_len = len - rem_len;
	block_nb = new_len / 128;
	shifted_message = message + rem_len;
	SHA512_transform(m_block, 1, md_data, sha512_k);
	SHA512_transform(shifted_message, block_nb, md_data, sha512_k);
	rem_len = new_len % 128;
	//memcpy(m_block, &shifted_message[block_nb << 7], rem_len);
	unsigned int block_nb1 = block_nb << 7;
	for (i = 0; i < rem_len; ++i)
		m_block[i] = shifted_message[block_nb1 + i];
	(*m_len) = rem_len;
	(*m_tot_len) += (block_nb + 1) << 7;
}

void SHA512_final(unsigned char *digest, unsigned long *md_data, unsigned char *m_block,
	unsigned int *m_tot_len, unsigned int *m_len,  unsigned long *sha512_k)
{
	unsigned int block_nb;
	unsigned int pm_len;
	unsigned int len_b;
	int i, id = get_global_id(0);
	//if (id == 1)
	//	printf("I = %d in Final\n", id);
	block_nb = 1 + ((128 - 17)
		< ((*m_len) % 128));
	len_b = ((*m_tot_len) + (*m_len)) << 3;
	pm_len = block_nb << 7;
	//memset(m_block + m_len, 0, pm_len - m_len);
	for (i = 0; i < pm_len - (*m_len); ++i)
		m_block[(*m_len) + i] = '\0';
	m_block[(*m_len)] = 0x80;
	SHA2_UNPACK32(len_b, m_block + pm_len - 4);
	SHA512_transform(m_block, block_nb, md_data, sha512_k);
	for (i = 0; i < 8; i++) {
		SHA2_UNPACK64(md_data[i], &digest[i << 3]);
	}
}


int getSBoxValue(int num)
{
	int sbox[256] = {
		//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
	return sbox[num];
}

// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).


// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
void KeyExpansion(unsigned char *RoundKey, unsigned char *Key)
{
	int i, j;
	unsigned char temp[4], k;
	int Rcon[255] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

	// The first round key is the key itself.
	for (i = 0; i<Nk; i++)
	{
		RoundKey[i * 4] = Key[i * 4];
		RoundKey[i * 4 + 1] = Key[i * 4 + 1];
		RoundKey[i * 4 + 2] = Key[i * 4 + 2];
		RoundKey[i * 4 + 3] = Key[i * 4 + 3];
	}

	// All other round keys are found from the previous round keys.
	while (i < (Nb * (Nr + 1)))
	{
		for (j = 0; j<4; j++)
		{
			temp[j] = RoundKey[(i - 1) * 4 + j];
		}
		if (i % Nk == 0)
		{
			// This function rotates the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;
			}

			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				temp[0] = getSBoxValue(temp[0]);
				temp[1] = getSBoxValue(temp[1]);
				temp[2] = getSBoxValue(temp[2]);
				temp[3] = getSBoxValue(temp[3]);
			}

			temp[0] = temp[0] ^ Rcon[i / Nk];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			// Function Subword()
			{
				temp[0] = getSBoxValue(temp[0]);
				temp[1] = getSBoxValue(temp[1]);
				temp[2] = getSBoxValue(temp[2]);
				temp[3] = getSBoxValue(temp[3]);
			}
		}
		RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
		RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
		RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
		RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
		i++;
	}
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(int round, unsigned char  *state, unsigned char *RoundKey)
{
	int i, j;
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			state[j * 4 + i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void InvSubBytes(unsigned char  *state)
{
	int rsbox[256] =
	{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
	, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
	, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
	, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
	, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
	, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
	, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
	, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
	, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
	, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
	, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
	, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
	, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
	, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
	, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
	, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


	int i, j;
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			state[i * 4 + j] = rsbox[state[i * 4 + j]];

		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void InvShiftRows(unsigned char  *state)
{
	unsigned char temp;

	// Rotate first row 1 columns to right	
	temp = state[1 * 4 + 3];
	state[1 * 4 + 3] = state[1 * 4 + 2];
	state[1 * 4 + 2] = state[1 * 4 + 1];
	state[1 * 4 + 1] = state[1 * 4 + 0];
	state[1 * 4 + 0] = temp;

	// Rotate second row 2 columns to right	
	temp = state[2 * 4 + 0];
	state[2 * 4 + 0] = state[2 * 4 + 2];
	state[2 * 4 + 2] = temp;

	temp = state[2 * 4 + 1];
	state[2 * 4 + 1] = state[2 * 4 + 3];
	state[2 * 4 + 3] = temp;

	// Rotate third row 3 columns to right
	temp = state[3 * 4 + 0];
	state[3 * 4 + 0] = state[3 * 4 + 1];
	state[3 * 4 + 1] = state[3 * 4 + 2];
	state[3 * 4 + 2] = state[3 * 4 + 3];
	state[3 * 4 + 3] = temp;
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
void InvMixColumns(unsigned char  *state)
{
	int i;
	unsigned char a, b, c, d;
	for (i = 0; i<4; i++)
	{

		a = state[0 * 4 + i];
		b = state[1 * 4 + i];
		c = state[2 * 4 + i];
		d = state[3 * 4 + i];


		state[0 * 4 + i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[1 * 4 + i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[2 * 4 + i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[3 * 4 + i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// InvCipher is the main function that decrypts the CipherText.
void InvCipher(unsigned char *in, unsigned char *out, unsigned char *RoundKey)
{
	int i, j, round = 0;
	unsigned char  state[16];
	//Copy the input CipherText to state array.
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			state[j * 4 + i] = in[i * 4 + j];
		}
	}

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(Nr, state, RoundKey);

	for (round = Nr - 1; round>0; round--)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		InvMixColumns(state);
	}

	//// The last round is given below.
	//// The MixColumns function is not here in the last round.
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(0, state, RoundKey);

	// The decryption process is over.
	// Copy the state array to output array.
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			out[i * 4 + j] = state[j * 4 + i];
		}
	}
}

int SetKeyFromPassphrase(
	 unsigned char *salt,  unsigned char *input, int inlen,
	int count, unsigned char *key, unsigned char *iv)
{
	unsigned int m_tot_len, m_len;
	unsigned char m_block[256], md_buf[64];
	unsigned long md_data[8];
	int niv = 16, nkey = 32, addmd = 0, saltlen = 8;
	int  k, I;
	 unsigned long sha512_k[80] = //ULL = unsigned long long
	{ 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL };

	for (;;)
	{
		md_data[0] = 0x6a09e667f3bcc908ULL;
		md_data[1] = 0xbb67ae8584caa73bULL;
		md_data[2] = 0x3c6ef372fe94f82bULL;
		md_data[3] = 0xa54ff53a5f1d36f1ULL;
		md_data[4] = 0x510e527fade682d1ULL;
		md_data[5] = 0x9b05688c2b3e6c1fULL;
		md_data[6] = 0x1f83d9abfb41bd6bULL;
		md_data[7] = 0x5be0cd19137e2179ULL;
		m_len = 0;
		m_tot_len = 0;

		if (addmd++)
			SHA512_update(md_buf, 64, md_data, m_block, &m_tot_len, &m_len, sha512_k);

		SHA512_update(input, inlen, md_data, m_block, &m_tot_len, &m_len, sha512_k);
		SHA512_update(salt, saltlen, md_data, m_block, &m_tot_len, &m_len, sha512_k);
		SHA512_final(md_buf, md_data, m_block, &m_tot_len, &m_len, sha512_k);

		for (k = 1; k < (unsigned int)count; k++)
		{
			md_data[0] = 0x6a09e667f3bcc908ULL;
			md_data[1] = 0xbb67ae8584caa73bULL;
			md_data[2] = 0x3c6ef372fe94f82bULL;
			md_data[3] = 0xa54ff53a5f1d36f1ULL;
			md_data[4] = 0x510e527fade682d1ULL;
			md_data[5] = 0x9b05688c2b3e6c1fULL;
			md_data[6] = 0x1f83d9abfb41bd6bULL;
			md_data[7] = 0x5be0cd19137e2179ULL;
			m_len = 0;
			m_tot_len = 0;

			SHA512_update(md_buf, 64, md_data, m_block, &m_tot_len, &m_len, sha512_k);
			SHA512_final(md_buf, md_data, m_block, &m_tot_len, &m_len, sha512_k);
		}
		I = 0;
		if (nkey)
		{
			for (;;)
			{
				if (nkey == 0) break;
				if (I == 64) break;
				*(key++) = md_buf[I];
				nkey--;
				I++;
			}
		}
		if (niv && (I != 64))
		{
			for (;;)
			{
				if (niv == 0) break;
				if (I == 64) break;
				*(iv++) = md_buf[I];
				niv--;
				I++;
			}
		}
		if ((nkey == 0) && (niv == 0)) break;
	}
	return 1;
}


bool Decrypt(uchar *in, uchar *out, uchar *Key, uchar *IV)
{
	int i, j;
	uchar RoundKey[240];
	uchar out1[16], c_i[16];

	for (j = 0; j < 16; ++j)
		c_i[j] = IV[j];
	//The Key-Expansion routine must be called before the decryption routine.
	KeyExpansion(RoundKey, Key);
	for (i = 0; i < 3; ++i){
		// The next function call decrypts the CipherText with the Key using AES algorithm.
		InvCipher(in + i * 16, out1, RoundKey);

		for (j = 0; j < 16; ++j)
			out[16 * i + j] = out1[j] ^ c_i[j];
		for (j = 0; j < 16; ++j)
			c_i[j] = in[i * 16 + j];
	}
	//if(cmp(default_pass, pass))
	//{
		for(i = 0; i < 48; ++i)
			printf("%d ", in[i]);
		for(i = 0; i < 48; ++i)
			printf("%d ", out[i]);
	//}
	//if(out[48] == 16)
		return true;
	//return false;
}

bool cmp(uchar *a, uchar *b)
{
	int i;
	for(i = 0; i < PASS_LEN; ++i)
		if(a[i] != b[i])
			return false;
	return true;
}

bool Unlock(uchar* pass, uchar *pMasterKey_second_vchSalt, uint pMasterKey_second_nDeriveIterations, uchar *vchCryptedKey, uchar *default_pass )
{
	uchar chKey[WALLET_CRYPTO_KEY_SIZE], chIV[WALLET_CRYPTO_KEY_SIZE], Key[48];
	int i, j;
	for (j = 0; j < 32; ++j)
		chKey[j] = '\0', chIV[j] = '\0';
	for (j = 0; j < 48; ++j)
		Key[j] = '\0';
	/*if(cmp(default_pass, pass))
	{
		for(i = 0; i < 32; ++i)
			printf("%d ", chKey[i]);
		for(i = 0; i < 32; ++i)
			printf("%d ", chIV[i]);
	}*/
	SetKeyFromPassphrase(pMasterKey_second_vchSalt, (unsigned char*)pass, PASS_LEN, pMasterKey_second_nDeriveIterations, chKey, chIV);
	if(cmp(default_pass, pass))
	{
		for(i = 0; i < 32; ++i)
			printf("%d ", chKey[i]);
		for(i = 0; i < 32; ++i)
			printf("%d ", chIV[i]);
		return true;
		//for(i = 0; i < 48; ++i)
		//	printf("%d ", vchCryptedKey[i]);
		
		//for(i = 0; i < 32; ++i)
		//	resKey[i] = chKey[i], resIV[i] = chIV[i];
	
	//if(Decrypt(vchCryptedKey, Key, chKey, chIV))
	//	return true;
	}
	return false;
}

__kernel void brute( __global uchar *result, ulong delitel, __global uchar *pMasterKey_second_vchSalt1,
uint pMasterKey_second_nDeriveIterations, __global uchar *pMasterKey_second_vchCryptedKey )
{
	uchar default_charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	// получаем текущий id.
	ulong gid = get_global_id(0), tmp, k;
	int i, j;
	tmp = gid;
	bool flag1, flag2;
	uchar pass1[PASS_LEN], pass2[PASS_LEN], default_pass[] = "00000";//"0Gz7n";
	uchar pMasterKey_second_vchSalt[8], vchCryptedKey[48];
	
	for (i = 0; i < 8; ++i)
		pMasterKey_second_vchSalt[i] = pMasterKey_second_vchSalt1[i];
	//pMasterKey_second_vchSalt[8] = '\0';
	for (i = 0; i < 48; ++i)
		vchCryptedKey[i] = pMasterKey_second_vchCryptedKey[i];
	//vchCryptedKey[48] = '\0';
	
	for (i = 0; i < PASS_LEN; ++i)
	{
		k = tmp / delitel;
		tmp = tmp % delitel;
		delitel /= ALPHA_LEN;
		pass1[i] = default_charset[k];
		pass2[i] = default_charset[ALPHA_LEN - 1 - k];
	}

	flag1 = 1, flag2 = 1;
	flag1 = Unlock(pass1, pMasterKey_second_vchSalt, pMasterKey_second_nDeriveIterations, vchCryptedKey, default_pass);
	flag2 = Unlock(pass2, pMasterKey_second_vchSalt, pMasterKey_second_nDeriveIterations, vchCryptedKey, default_pass);
	//if(cmp(default_pass, pass1))
	//	for(i = 0; i < 32; ++i)
	//		key[i] = resKey[i], iv[i] = resIV[i];
	if (flag1)
		for(i = 0; i < PASS_LEN; ++i)
			result[i] = pass1[i];
	if (flag2)
		for(i = 0; i < PASS_LEN; ++i)
			result[i] = pass2[i];
		//printf("%s", pass);					
}

// End of kernel1.cl