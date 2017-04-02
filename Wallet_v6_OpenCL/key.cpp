#include "key.h"

//#include "arith_uint256.h"
#include "common.h"
//#include "hmac_sha512.h"
#include "eccryptoverify.h"
#include "pubkey.h"
#include <openssl/rand.h>
//#include "random.h"

//#include "secp256k1.h"
//#include "ecwrapper.h"

//static secp256k1_context_t* secp256k1_context = NULL;

bool CKey::Check(const unsigned char *vch) {
    return eccrypto::Check(vch);
}




bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    if (!fValid)
        return false;
    vchSig.resize(72);
    int nSigLen = 72;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
   // int ret = secp256k1_ecdsa_sign(secp256k1_context, hash.begin(), (unsigned char*)&vchSig[0], &nSigLen, begin(), secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : NULL);
   // assert(ret);
    vchSig.resize(nSigLen);
    return true;
}

void GetRandBytes(unsigned char* buf, int num)
{
	if (RAND_bytes(buf, num) != 1) {
		printf("%s: OpenSSL RAND_bytes() failed with error: ");
		assert(false);
	}
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (pubkey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

