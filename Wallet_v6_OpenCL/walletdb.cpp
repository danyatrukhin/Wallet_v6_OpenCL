#include "walletdb.h"

#include "wallet.h"
#include <db_cxx.h>

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>

#include "streams.h"
#include "tinyformat.h"
#include "uint256.h"
#include "db.h"
#include "clientversion.h"
//#include "script.h"

using namespace std;
static uint64_t nAccountingEntryNumber = 0;
CryptedKeyMap mapCryptedKeys;
typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
MasterKeyMap mapMasterKeys;
unsigned int nMasterKeyMaxID = 0;

//
// CWalletDB
//

class CWalletScanState {
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool
ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, string& strType, string& strErr)
{
    try {
    //    // Unserialize
    //    // Taking advantage of the fact that pair serialization
    //    // is just the two items serialized one after the other
        ssKey >> strType;
		if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            mapMasterKeys[nID] = kMasterKey;
            if (nMasterKeyMaxID < nID)
                nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            vector<unsigned char> vchPubKey;
            ssKey >> vchPubKey;
            vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!AddCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        
      }catch (...)
    {
        return false;
    }
    return true;
}

bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
	mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
   
    return true;
}

static bool IsKeyType(string strType)
{
    return (strType== "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors LoadWallet(CWallet* pwallet)
{
   // pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
       

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            printf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                printf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
            }
            if (!strErr.empty())
                printf("%s\n", strErr);
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }

    //if (fNoncriticalErrors && result == DB_LOAD_OK)
    //    result = DB_NONCRITICAL_ERROR;
	//
    //// Any wallet corruption at all: skip any rewriting or
    //// upgrading, we don't want to make it worse.
    //if (result != DB_LOAD_OK)
    //    return result;
	//
    //printf("nFileVersion = %d\n", wss.nFileVersion);
	//
    //printf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
    //       wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);
	//
    //// nTimeFirstKey is only reliable if all keys have metadata
    //if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
    //    pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'
	//
    //BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
    //    WriteTx(hash, pwallet->mapWallet[hash]);
	//
    //// Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    //if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
    //    return DB_NEED_REWRITE;
	//
    //if (wss.nFileVersion < CLIENT_VERSION) // Update
    //    WriteVersion(CLIENT_VERSION);
	//
    //if (wss.fAnyUnordered)
    //   result = ReorderTransactions(pwallet);

    return result;
}