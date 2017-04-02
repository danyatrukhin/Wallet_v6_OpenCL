#include <shlobj.h>
//#include <boost/filesystem.hpp>

//boost::filesystem::path GetSpecialFolderPath(int nFolder)
//{
//    namespace fs = boost::filesystem;
//
//    char pszPath[MAX_PATH] = "";
//	GetSpecialFolderPath(nFolder);
//   if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, false))
//   {
//       return fs::path(pszPath);
//   }
//
//    printf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
//    return fs::path("");
//}
boost::filesystem::path GetDataDir()
{
	//return GetSpecialFolderPath(CSIDL_APPDATA) / "Bitcoin";
	return "C:\\Bitcoin";// C:\\Users\\Viktoria\\AppData\\Roaming\\Bitcoin
}