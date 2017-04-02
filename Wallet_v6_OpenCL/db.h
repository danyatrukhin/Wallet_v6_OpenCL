#ifndef BITCOIN_WALLET_DB_H
#define BITCOIN_WALLET_DB_H

#include "serialize.h"
#include "streams.h"

#include <map>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <db_cxx.h>


Db* pdb;

Dbc* GetCursor(bool difference)
{
    if (!pdb)
        return NULL;
    Dbc* pcursor = NULL;
    int ret = pdb->cursor(NULL, &pcursor, 0);
    if (ret != 0)
        return NULL;
    return pcursor;
}

int ReadAtCursor(Dbc* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags = DB_NEXT)
{
    // Read at cursor
    Dbt datKey;
    if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
        datKey.set_data(&ssKey[0]);
        datKey.set_size(ssKey.size());
    }
    Dbt datValue;
    if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
        datValue.set_data(&ssValue[0]);
        datValue.set_size(ssValue.size());
    }
    datKey.set_flags(DB_DBT_MALLOC);
    datValue.set_flags(DB_DBT_MALLOC);
    int ret = pcursor->get(&datKey, &datValue, fFlags);
    if (ret != 0)
        return ret;
    else if (datKey.get_data() == NULL || datValue.get_data() == NULL)
        return 99999;

    // Convert to streams
    ssKey.SetType(SER_DISK);
    ssKey.clear();
    ssKey.write((char*)datKey.get_data(), datKey.get_size());
    ssValue.SetType(SER_DISK);
    ssValue.clear();
    ssValue.write((char*)datValue.get_data(), datValue.get_size());

    // Clear memory
    memset(datKey.get_data(), 0, datKey.get_size());
    memset(datValue.get_data(), 0, datValue.get_size());
    return 0;
}


#endif // BITCOIN_WALLET_DB_H