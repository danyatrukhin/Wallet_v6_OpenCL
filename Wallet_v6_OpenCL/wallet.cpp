#include "wallet.h"


bool Open(const boost::filesystem::path& pathIn)
{
    boost::filesystem::path pathLogDir = pathIn / "database";
    boost::filesystem::create_directory(pathLogDir);
    boost::filesystem::path pathErrorFile = pathIn / "db.log";

	dbenv = new DbEnv(DB_CXX_NO_EXCEPTIONS);

    dbenv->set_lg_dir(pathLogDir.string().c_str());
    dbenv->set_cachesize(0, 0x100000, 1); // 1 MiB should be enough for just the wallet
    dbenv->set_lg_bsize(0x10000);
    dbenv->set_lg_max(1048576);
    dbenv->set_lk_max_locks(40000);
    dbenv->set_lk_max_objects(40000);
    dbenv->set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->set_flags(DB_TXN_WRITE_NOSYNC, 1);
    dbenv->log_set_config(DB_LOG_AUTO_REMOVE, 1);
	
    int ret = dbenv->open(pathIn.string().c_str(),
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_RECOVER,
                         S_IRUSR | S_IWUSR);
    if (ret != 0)
	{
		printf("CDBEnv::Open: Error %d opening database environment: %s\n", ret, DbEnv::strerror(ret));
        return false;
	}
    fMockDbg = false;
    return true;
}

bool IsMock() { return fMockDbg; }

 template <typename K>
    bool Exists(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Exists
        int ret = pdb->exists(activeTxn, &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0);
    }
template <typename K, typename T>
bool Write(const K& key, const T& value, bool fOverwrite = true)
{
    if (!pdb)
        return false;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(1000);
    ssKey << key;
    Dbt datKey(&ssKey[0], ssKey.size());

    // Value
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue.reserve(10000);
    ssValue << value;
    Dbt datValue(&ssValue[0], ssValue.size());

    // Write
    int ret = pdb->put(activeTxn, &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

    // Clear memory in case it was a private key
    memset(datKey.get_data(), 0, datKey.get_size());
    memset(datValue.get_data(), 0, datValue.get_size());
    return (ret == 0);
}
bool WriteVersion(int nVersion)
{
    return Write(std::string("version"), nVersion);
}
void pdb_start(const std::string& strFilename, const char* pszMode, bool fFlushOnCloseIn)
{
	int ret;
    if (strFilename.empty())
        return;

    bool fCreate = strchr(pszMode, 'c') != NULL;
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

 
        if (!Open(GetDataDir()))
            throw runtime_error("CDB: Failed to open database environment.");

        const std::string& strFile = strFilename;
        ++mapFileUseCount[strFile];
        pdb = mapDb[strFile];
        if (pdb == NULL) {
            pdb = new Db(dbenv, 0);

            bool fMockDb = IsMock();
            if (fMockDb) {
                DbMpoolFile* mpf = pdb->get_mpf();
                ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0)
                    throw runtime_error(strprintf("CDB: Failed to configure for no temp file backing for database %s", strFile));
            }

            ret = pdb->open(NULL,                               // Txn pointer
                            fMockDb ? NULL : strFile.c_str(),   // Filename
                            fMockDb ? strFile.c_str() : "main", // Logical db name
                            DB_BTREE,                           // Database type
                            nFlags,                             // Flags
                            0);

            if (ret != 0) {
                delete pdb;
                pdb = NULL;
                --mapFileUseCount[strFile];
                throw runtime_error(strprintf("CDB: Error %d, can't open database %s", ret, strFile));
            }

            if (fCreate && !Exists(string("version"))) {

                WriteVersion(CLIENT_VERSION);
            }

            mapDb[strFile] = pdb;
        }
}
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
ReadKeyValue(CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, string& strType)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
		if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(mapMasterKeys.count(nID) != 0)
            {
                printf("Error reading wallet database: duplicate CMasterKey id %u", nID);
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
                cout << "Error reading wallet database: LoadCryptedKey failed";
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

DBErrors LoadWallet(std::string strFilename)
{
	pdb_start(strFilename, "r+", true);
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
       

        // Get cursor
        Dbc* pcursor = GetCursor(true);
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
            string strType;
           if (!ReadKeyValue(ssKey, ssValue, wss, strType))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }
	mapDb[strFilename]->close(0);
	pdb->close(0);
    return result;
}

int EVP_BytesToKeyy(const EVP_CIPHER *type, const EVP_MD *md,
	const unsigned char *salt, const unsigned char *data, int datal,
	int count, unsigned char *key, unsigned char *iv)
{
	EVP_MD_CTX c;
	unsigned char md_buf[EVP_MAX_MD_SIZE];
	int niv, nkey, addmd = 0;
	unsigned int mds = 0, i;
	int rv = 0;
	nkey = type->key_len;
	niv = type->iv_len;
	OPENSSL_assert(nkey <= EVP_MAX_KEY_LENGTH);
	OPENSSL_assert(niv <= EVP_MAX_IV_LENGTH);

	if (data == NULL) return(nkey);

	EVP_MD_CTX_init(&c);
	for (;;)
	{
		if (!EVP_DigestInit_ex(&c, md, NULL))
			return 0;
		if (addmd++)
			if (!EVP_DigestUpdate(&c, &(md_buf[0]), mds))
				goto err;
		if (!EVP_DigestUpdate(&c, data, datal))
			goto err;
		if (salt != NULL)
			if (!EVP_DigestUpdate(&c, salt, PKCS5_SALT_LEN))
				goto err;
		if (!EVP_DigestFinal_ex(&c, &(md_buf[0]), &mds))
			goto err;

		for (i = 1; i<(unsigned int)count; i++)
		{
			if (!EVP_DigestInit_ex(&c, md, NULL))
				goto err;
			if (!EVP_DigestUpdate(&c, &(md_buf[0]), mds))
				goto err;
			if (!EVP_DigestFinal_ex(&c, &(md_buf[0]), &mds))
				goto err;
		}
		i = 0;
		if (nkey)
		{
			for (;;)
			{
				if (nkey == 0) break;
				if (i == mds) break;
				if (key != NULL)
					*(key++) = md_buf[i];
				nkey--;
				i++;
			}
		}
		if (niv && (i != mds))
		{
			for (;;)
			{
				if (niv == 0) break;
				if (i == mds) break;
				if (iv != NULL)
					*(iv++) = md_buf[i];
				niv--;
				i++;
			}
		}
		if ((nkey == 0) && (niv == 0)) break;
	}
	rv = type->key_len;
err:
	EVP_MD_CTX_cleanup(&c);
	OPENSSL_cleanse(&(md_buf[0]), EVP_MAX_MD_SIZE);
	return rv;
}

bool SetKeyFromPassphrase(const SecureString& strKeyData, const std::vector<unsigned char>& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = EVP_BytesToKeyy(EVP_aes_256_cbc(), EVP_sha512(), &chSalt[0],
                          (unsigned char *)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);
	
    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(chKey, sizeof(chKey));
        memory_cleanse(chIV, sizeof(chIV));
        return false;
    }

    return true;
}

bool Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext)
{


    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();
    int nPLen = nLen, nFLen = 0;

    vchPlaintext = CKeyingMaterial(nPLen);

	//for (int i = 0; i < nLen; ++i)
	//	printf("0x%02x, ", vchCiphertext.data[i]);
	//std::cout << vchCiphertext.data << std::endl;

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, &vchPlaintext[0], &nPLen, &vchCiphertext[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, (&vchPlaintext[0]) + nPLen, &nFLen) != 0;

	EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;
    return true;
}

bool fDecryptionThoroughlyChecked;

CKeyingMaterial vMasterKey;

bool SetKey(const CKeyingMaterial& chNewKey, const std::vector<unsigned char>& chNewIV)
{
	if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_KEY_SIZE)
		return false;

	memcpy(&chKey[0], &chNewKey[0], sizeof chKey);
	memcpy(&chIV[0], &chNewIV[0], sizeof chIV);

	//fKeySet = true;
	return true;
}

static bool DecryptSecret(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCiphertext, const uint256& nIV, CKeyingMaterial& vchPlaintext)
{
	std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
	memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
	if (SetKey(vMasterKey, chIV))
		return false;
	return Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}

static bool DecryptKey(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCryptedSecret, const CPubKey& vchPubKey, CKey& key)
{
	CKeyingMaterial vchSecret;
	if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
		return false;

	if (vchSecret.size() != 32)
		return false;

	key.Set(vchSecret.begin(), vchSecret.end(), vchPubKey.IsCompressed());
	return key.VerifyPubKey(vchPubKey);
}

bool Unlock1(const CKeyingMaterial& vMasterKeyIn)
{

	bool keyPass = false;
	bool keyFail = false;
	CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
	for (; mi != mapCryptedKeys.end(); ++mi)
	{
		const CPubKey &vchPubKey = (*mi).second.first;
		const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
		CKey key;
		if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, key))
		{
			keyFail = true;
			break;
		}
		keyPass = true;
		if (fDecryptionThoroughlyChecked)
			break;
	}
	if (keyPass && keyFail)
	{
		printf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
		assert(false);
	}
	if (keyFail || !keyPass)
		return false;
	vMasterKey = vMasterKeyIn;
	fDecryptionThoroughlyChecked = true;
	return true;
}

bool Unlock(const SecureString& strWalletPassphrase)
{
    CKeyingMaterial vMasterKey;
    BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
    {
        if(!SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
            return false;
		//for (int i = 0; i < 48; ++i)
		//	printf("0x%02x, ", pMasterKey.second.vchCryptedKey[i]);
		//printf("\n");
        if (!Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
			continue;//return true;
		if (Unlock1(vMasterKey))
			return true;
    }
    return false;
}

/* convert the kernel file into a string */
int convertToString(const char *filename, std::string& s)
{
	size_t size;
	char*  str;
	std::fstream f(filename, (std::fstream::in | std::fstream::binary));

	if (f.is_open())
	{
		size_t fileSize;
		f.seekg(0, std::fstream::end);
		size = fileSize = (size_t)f.tellg();
		f.seekg(0, std::fstream::beg);
		str = new char[size + 1];
		if (!str)
		{
			f.close();
			return 0;
		}

		f.read(str, fileSize);
		f.close();
		str[size] = '\0';
		s = str;
		delete[] str;
		return 0;
	}
	cout << "Error: failed to open file\n:" << filename << endl;
	return 1;
}

#include <CL/cl.h>
#include <cstring>

#define PASS_LEN 5
#define ALPHA_LEN 62
#define MAX_SOURCE_SIZE 1048576
#include <iostream>
using namespace std;

#define CL_CHECK(_expr)                                                         \
do {																			\
	cl_int _err = _expr;														\
if (_err == CL_SUCCESS)															\
	break;																		\
	fprintf(stderr, "OpenCL Error: '%s' returned %d!\n", #_expr, (int)_err);	\
	abort();																	\
} while (0)

int main()
{
	//bool ret;

	LoadWallet("wallet.dat");

	SecureString WalletPass;
	WalletPass.reserve(100);

	//cout << "Enter Password: ";
	//cin >> WalletPass;
	WalletPass = "LinkinPark77";//GfhjkmFlvbyf1%

	/*ret = Unlock(WalletPass);
	if (ret)
	cout << "password is correct.\n";
	else
	cout << "password is incorrect.\n";
	*/
	cl_uint ret_num_platforms, ret_num_devices = 0;
	cl_int ret;
	//cl_platform_id platform_id;
	//cl_device_id device_id;
	cl_context context;
	cl_command_queue command_queue;
	cl_program program = NULL;
	cl_kernel kernel = NULL;

	// получить доступные платформы 
	/*ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);

	// получить доступные устройства
	ret = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, &ret_num_devices);*/
	cl_uint numPlatforms;	//the NO. of platforms
	cl_platform_id platform = NULL;	//the chosen platform
	
	cl_int	status = clGetPlatformIDs(0, NULL, &numPlatforms);
	
	cl_int status_build;
	if (status != CL_SUCCESS)
	{
		cout << "Error: Getting platforms!" << endl;
		return 1;
	}

	/*For clarity, choose the first available platform. */
	if (numPlatforms > 0)
	{
		cl_platform_id* platforms = (cl_platform_id*)malloc(numPlatforms* sizeof(cl_platform_id));
		status = clGetPlatformIDs(numPlatforms, platforms, NULL);
		platform = platforms[0];


		printf("=== %d OpenCL platform(s) found: ===\n", numPlatforms);
		for (int i = 0; i < numPlatforms; i++)
		{
			char buffer[10240];
			printf("  -- %d --\n", i);
			CL_CHECK(clGetPlatformInfo(platforms[i], CL_PLATFORM_PROFILE, 10240, buffer, NULL));
			printf("  PROFILE = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platforms[i], CL_PLATFORM_VERSION, 10240, buffer, NULL));
			printf("  VERSION = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, 10240, buffer, NULL));
			printf("  NAME = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platforms[i], CL_PLATFORM_VENDOR, 10240, buffer, NULL));
			printf("  VENDOR = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platforms[i], CL_PLATFORM_EXTENSIONS, 10240, buffer, NULL));
			printf("  EXTENSIONS = %s\n", buffer);
		}
		free(platforms);
	}

	/*Step 2:Query the platform and choose the first GPU device if has one.Otherwise use the CPU as device.*/
	cl_uint				numDevices = 0;
	cl_device_id        *devices;
	status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, NULL, &numDevices);
	if (numDevices == 0)	//no GPU available.
	{
		cout << "No GPU device available." << endl;
		cout << "Choose CPU as default device." << endl;
		status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, 0, NULL, &numDevices);
		devices = (cl_device_id*)malloc(numDevices * sizeof(cl_device_id));
		status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, numDevices, devices, NULL);
	}
	else
	{
		devices = (cl_device_id*)malloc(numDevices * sizeof(cl_device_id));
		status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, numDevices, devices, NULL);
	}
	printf("=== %d OpenCL device(s) found on platform:\n", numPlatforms);
	for (int i = 0; i<numDevices; i++)
	{
		char buffer[10240];
		cl_uint buf_uint;
		cl_ulong buf_ulong;
		printf("  -- %d --\n", i);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DEVICE_NAME, sizeof(buffer), buffer, NULL));
		printf("  DEVICE_NAME = %s\n", buffer);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DEVICE_VENDOR, sizeof(buffer), buffer, NULL));
		printf("  DEVICE_VENDOR = %s\n", buffer);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DEVICE_VERSION, sizeof(buffer), buffer, NULL));
		printf("  DEVICE_VERSION = %s\n", buffer);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DRIVER_VERSION, sizeof(buffer), buffer, NULL));
		printf("  DRIVER_VERSION = %s\n", buffer);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(buf_uint), &buf_uint, NULL));
		printf("  DEVICE_MAX_COMPUTE_UNITS = %u\n", (unsigned int)buf_uint);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(buf_uint), &buf_uint, NULL));
		printf("  DEVICE_MAX_CLOCK_FREQUENCY = %u\n", (unsigned int)buf_uint);
		CL_CHECK(clGetDeviceInfo(devices[i], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(buf_ulong), &buf_ulong, NULL));
		printf("  DEVICE_GLOBAL_MEM_SIZE = %llu\n", (unsigned long long)buf_ulong);
	}
	//clGetDeviceInfo(devices[0],)
	// создать контекст 
	context = clCreateContext(NULL, 1, devices, NULL, NULL, &ret);

	// создаем команду 
	command_queue = clCreateCommandQueue(context, devices[0], 0, &ret);

	/*FILE *fp;
	const char fileName[] = "kernel1.cl";
	size_t source_size;
	char *source_str;
	int i;

	try {
		fp = fopen(fileName, "r");
		if (!fp) {
			fprintf(stderr, "Failed to load kernel.\n");
			exit(1);
		}
		source_str = (char *)malloc(MAX_SOURCE_SIZE);
		source_size = fread(source_str, 1, MAX_SOURCE_SIZE, fp);
		fclose(fp);
	}
	catch (int a) {
		printf("%f", a);
	}*/
	char *filename = "kernel1.cl";
	string sourceStr;
	status = convertToString(filename, sourceStr);
	const char *source = sourceStr.c_str();
	size_t sourceSize[] = { strlen(source) };


	/* создать бинарник из кода программы */
	program = clCreateProgramWithSource(context, 1, &source, sourceSize, &ret);
	if (!program) exit(-1);
	/* скомпилировать программу */
	ret = clBuildProgram(program, 1, devices, NULL, NULL, NULL);

	if (ret != CL_SUCCESS) {
		// Determine the size of the log
		size_t log_size;
		clGetProgramBuildInfo(program, devices[0], CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);

		// Allocate memory for the log
		char *log = (char *)malloc(log_size);

		// Get the log
		clGetProgramBuildInfo(program, devices[0], CL_PROGRAM_BUILD_LOG, log_size, log, NULL);

		// Print the log
		printf("%s\n", log);
	}

	/* создать кернел */
	kernel = clCreateKernel(program, "brute", &ret);

	cl_mem memobj = NULL, RESULT = NULL, Salt = NULL, Crypted = NULL, CHIV = NULL, CHKey = NULL;
	int memLenth = 10;
	cl_int* mem = (cl_int *)malloc(sizeof(cl_int)* memLenth);
	cl_uchar pass[PASS_LEN];
	int i;
	 

	BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
	{
		cl_uchar salt[8], cryp[48];
		cl_uint iter;
		for (i = 0; i < 8; ++i)
			salt[i] = pMasterKey.second.vchSalt[i];
		for (i = 0; i < 48; ++i)
			cryp[i] = pMasterKey.second.vchCryptedKey[i];
		iter = pMasterKey.second.nDeriveIterations;
		/* записать данные в буфер */
		/* создать буфер */
		//memobj = clCreateBuffer(context, CL_MEM_READ_WRITE, memLenth * sizeof(cl_int), NULL, &ret);
		RESULT = clCreateBuffer(context, CL_MEM_WRITE_ONLY, PASS_LEN * sizeof(cl_uchar), NULL, &ret);
		Salt = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, 8 * sizeof(cl_uchar), (void *)salt, &ret);
		Crypted = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, 48 * sizeof(cl_uchar), (void *)cryp, &ret);
	//	CHKey = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32 * sizeof(cl_uchar), NULL, &ret);
	//	CHIV = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32 * sizeof(cl_uchar), NULL, &ret);

		/* устанавливаем параметр */
		//ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&memobj);
		ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&RESULT);
		cl_ulong delitel = 1;
		for (int j = 0; j < PASS_LEN - 1; ++j)
			delitel *= ALPHA_LEN;
		ret = clSetKernelArg(kernel, 1, sizeof(cl_ulong), &delitel);
		ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&Salt);
		ret = clSetKernelArg(kernel, 3, sizeof(cl_uint), &iter);
		ret = clSetKernelArg(kernel, 4, sizeof(cl_mem), (void *)&Crypted);
	//	ret = clSetKernelArg(kernel, 5, sizeof(cl_mem), (void *)&CHKey);
	//	ret = clSetKernelArg(kernel, 6, sizeof(cl_mem), (void *)&CHIV);

		size_t global_work_size[1] = { ALPHA_LEN * ALPHA_LEN/*pow(ALPHA_LEN, PASS_LEN) / 2*/ };

		/* выполнить кернел */
		ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, global_work_size, NULL, 0, NULL, NULL);

		/* считать данные из буфера */
		ret = clEnqueueReadBuffer(command_queue, RESULT, CL_TRUE, 0, PASS_LEN * sizeof(cl_uchar), pass, 0, NULL, NULL);
		//ret = clEnqueueReadBuffer(command_queue, CHKey, CL_TRUE, 0, 32 * sizeof(cl_uchar), chKey, 0, NULL, NULL);
		//ret = clEnqueueReadBuffer(command_queue, CHIV, CL_TRUE, 0, 32 * sizeof(cl_uchar), chIV, 0, NULL, NULL);

		//for (i = 0; i < 32; ++i)
		//	printf("%c ", chKey[i]);
		//for (i = 0; i < 32; ++i)
		//	printf("%c ", chIV[i]);

		cout << endl << pass << endl;
	}

	system("pause");
	memory_cleanse(chKey, sizeof(chKey));
	memory_cleanse(chIV, sizeof(chIV));
	/*Step 12: Clean the resources.*/

	//status = clReleaseMemObject(Key);		//Release mem object.
	status = clReleaseMemObject(RESULT);		//Release mem object.
	status = clReleaseMemObject(Salt);		//Release mem object.
	status = clReleaseMemObject(CHKey);		//Release mem object.
	status = clReleaseMemObject(CHIV);		//Release mem object.
	status = clReleaseMemObject(Crypted);		//Release mem object.
	status = clReleaseKernel(kernel);
	status = clReleaseProgram(program);				//Release the program object.
	status = clReleaseCommandQueue(command_queue);	//Release  Command queue.
	status = clReleaseContext(context);				//Release context.

	if (devices != NULL)
	{
		free(devices);
		devices = NULL;
	}

	dbenv->close(0);

	return 0;
}