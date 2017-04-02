//#include "wallet.h"
#include "pubkey.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

namespace
{
	/* Global secp256k1_context object used for verification. */
	secp256k1_context* secp256k1_context_verify = NULL;
}
//#include "ecwrapper.h"
static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
	size_t rpos, rlen, spos, slen;
	size_t pos = 0;
	size_t lenbyte;
	unsigned char tmpsig[64] = { 0 };
	int overflow = 0;

	/* Hack to initialize sig with a correctly-parsed but invalid signature. */
	secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

	/* Sequence tag byte */
	if (pos == inputlen || input[pos] != 0x30) {
		return 0;
	}
	pos++;

	/* Sequence length bytes */
	if (pos == inputlen) {
		return 0;
	}
	lenbyte = input[pos++];
	if (lenbyte & 0x80) {
		lenbyte -= 0x80;
		if (pos + lenbyte > inputlen) {
			return 0;
		}
		pos += lenbyte;
	}

	/* Integer tag byte for R */
	if (pos == inputlen || input[pos] != 0x02) {
		return 0;
	}
	pos++;

	/* Integer length for R */
	if (pos == inputlen) {
		return 0;
	}
	lenbyte = input[pos++];
	if (lenbyte & 0x80) {
		lenbyte -= 0x80;
		if (pos + lenbyte > inputlen) {
			return 0;
		}
		while (lenbyte > 0 && input[pos] == 0) {
			pos++;
			lenbyte--;
		}
		if (lenbyte >= sizeof(size_t)) {
			return 0;
		}
		rlen = 0;
		while (lenbyte > 0) {
			rlen = (rlen << 8) + input[pos];
			pos++;
			lenbyte--;
		}
	}
	else {
		rlen = lenbyte;
	}
	if (rlen > inputlen - pos) {
		return 0;
	}
	rpos = pos;
	pos += rlen;

	/* Integer tag byte for S */
	if (pos == inputlen || input[pos] != 0x02) {
		return 0;
	}
	pos++;

	/* Integer length for S */
	if (pos == inputlen) {
		return 0;
	}
	lenbyte = input[pos++];
	if (lenbyte & 0x80) {
		lenbyte -= 0x80;
		if (pos + lenbyte > inputlen) {
			return 0;
		}
		while (lenbyte > 0 && input[pos] == 0) {
			pos++;
			lenbyte--;
		}
		if (lenbyte >= sizeof(size_t)) {
			return 0;
		}
		slen = 0;
		while (lenbyte > 0) {
			slen = (slen << 8) + input[pos];
			pos++;
			lenbyte--;
		}
	}
	else {
		slen = lenbyte;
	}
	if (slen > inputlen - pos) {
		return 0;
	}
	spos = pos;
	pos += slen;

	/* Ignore leading zeroes in R */
	while (rlen > 0 && input[rpos] == 0) {
		rlen--;
		rpos++;
	}
	/* Copy R value */
	if (rlen > 32) {
		overflow = 1;
	}
	else {
		memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
	}

	/* Ignore leading zeroes in S */
	while (slen > 0 && input[spos] == 0) {
		slen--;
		spos++;
	}
	/* Copy S value */
	if (slen > 32) {
		overflow = 1;
	}
	else {
		memcpy(tmpsig + 64 - slen, input + spos, slen);
	}

	if (!overflow) {
		overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
	}
	if (overflow) {
		/* Overwrite the result again with a correctly-parsed but invalid
		signature if parsing failed. */
		memset(tmpsig, 0, 64);
		secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
	}
	return 1;
}

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
	if (!IsValid())
		return false;
	secp256k1_pubkey pubkey;
	secp256k1_ecdsa_signature sig;
	if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
		return false;
	}
	if (vchSig.size() == 0) {
		return false;
	}
	if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size())) {
		return false;
	}
	/* libsecp256k1's ECDSA verification requires lower-S signatures, which have
	* not historically been enforced in Bitcoin, so normalize them first. */
	secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);
	return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig, hash.begin(), &pubkey);
}
