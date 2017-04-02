#include <openssl/aes.h>
#include <openssl/evp.h>

#ifdef WIN32
#ifndef S_IRUSR
#define S_IRUSR             0400
#define S_IWUSR             0200
#endif
#else
#define MAX_PATH            1024
#endif

#include <assert.h>
#include <db_cxx.h>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>
//

#include "streams.h"
#include "tinyformat.h"
#include "uint256.h"
#include "db.h"
#include "clientversion.h"
#include "secure.h"
#include "pubkey.h"
//#include "crypter.h"
//#include <secp256k1.h>
#include "eccryptoverify.h"
#include "dir.h"
#include "key.h"
//#include "serialize.h"

using namespace std;

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

/**
 * Settings
 */
unsigned int nTxConfirmTarget = 1;
bool bSpendZeroConfChange = true;
bool fSendFreeTransactions = false;
bool fPayAtLeastCustomFee = true;
bool fValid = false;
bool fMockDbg = false;
DbTxn* activeTxn = NULL;


const unsigned int WALLET_CRYPTO_KEY_SIZE = 32;
const unsigned int WALLET_CRYPTO_SALT_SIZE = 8;

unsigned char chKey[WALLET_CRYPTO_KEY_SIZE];
unsigned char chIV[WALLET_CRYPTO_KEY_SIZE];
CryptedKeyMap mapCryptedKeys;

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */

using namespace std;

class CMasterKey
{
public:
	std::vector<unsigned char> vchCryptedKey;
	std::vector<unsigned char> vchSalt;
	//! 0 = EVP_sha512()
	//! 1 = scrypt()
	unsigned int nDerivationMethod;
	unsigned int nDeriveIterations;
	//! Use this for more parameters to key derivation,
	//! such as the various parameters to scrypt
	std::vector<unsigned char> vchOtherDerivationParameters;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchCryptedKey);
		READWRITE(vchSalt);
		READWRITE(nDerivationMethod);
		READWRITE(nDeriveIterations);
		READWRITE(vchOtherDerivationParameters);
	}

	CMasterKey()
	{
		// 25000 rounds is just under 0.1 seconds on a 1.86 GHz Pentium M
		// ie slightly lower than the lowest hardware we need bother supporting
		nDeriveIterations = 25000;
		nDerivationMethod = 0;
		vchOtherDerivationParameters = std::vector<unsigned char>(0);
	}
};


static uint64_t nAccountingEntryNumber = 0;
typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
MasterKeyMap mapMasterKeys;
unsigned int nMasterKeyMaxID = 0;
unsigned char vch[32];
bool fCompressed;
std::map<std::string, int> mapFileUseCount;
std::map<std::string, Db*> mapDb;
DbEnv *dbenv;
bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);

enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};
bool Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext);
bool Unlock1(const CKeyingMaterial& vMasterKeyIn);
DBErrors LoadWallet(std::string strFilename);