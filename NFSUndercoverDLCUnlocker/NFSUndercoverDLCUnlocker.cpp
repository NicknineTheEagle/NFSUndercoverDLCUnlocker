#include <Windows.h>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>

#include <MinHook.h>
#include <Hooking.Patterns.h>

HMODULE g_module = NULL;
std::vector<std::string> g_dlcList;

typedef void( _fastcall *UPDATEPARTDBFUNC )( void *_this, void *_edx,
	int nArraySize,
	char *pContentData,
	const char *curKey );
UPDATEPARTDBFUNC ContentManager_UpdatePartDB = NULL;

void __fastcall ContentManager_EnumerateContent( void *_this, void *_edx )
{
	std::vector<char> buf;
	for ( const std::string &dlc : g_dlcList )
	{
		buf.insert( buf.end(), dlc.begin(), dlc.end() );
		buf.insert( buf.end(), { '\r', '\n' } );
	}
	buf.push_back( '\0' );

	ContentManager_UpdatePartDB( _this, NULL, buf.size() - 1, buf.data(), NULL );
}

bool g_initialized = false;

void Initialize()
{
	if ( g_initialized )
		return;

	auto test = hook::pattern(
		"6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC "
		"50 A1 ? ? ? ? 33 C4 89 44 24 4C 56 A1 ? ? "
		"? ? 33 C4 50 8D 44 24 58 64 A3 00 00 00 00 A1 "
		"? ? ? ? 8B 40 04"
	);
	if ( test.empty() )
		return;

	g_initialized = true;

	WCHAR pathStr[MAX_PATH];
	GetModuleFileNameW( g_module, pathStr, ARRAYSIZE( pathStr ) );
	std::filesystem::path modulePath( pathStr );

	// Read the list of unlocks.
	std::ifstream file( modulePath.parent_path() / L"dlc.txt" );
	if ( !file.is_open() )
		return;

	std::string str;
	while ( std::getline( file, str ) )
	{
		if ( str.empty() )
			continue;

		g_dlcList.push_back( str );
	}

	auto pattern_EnumerateContent = hook::pattern(
		"6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC "
		"50 A1 ? ? ? ? 33 C4 89 44 24 4C 56 A1 ? ? "
		"? ? 33 C4 50 8D 44 24 58 64 A3 00 00 00 00 A1 "
		"? ? ? ? 8B 40 04"
	);
	if ( pattern_EnumerateContent.empty() )
		return;

	auto pattern_UpdatePartDB = hook::pattern(
		"81 EC 08 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 "
		"04 01 00 00 83 BC 24 10 01 00 00 00 56 8B F1 0F "
		"84 ? ? ? ? 57 8B BC 24 14 01 00 00"
	);
	if ( pattern_UpdatePartDB.empty() )
		return;

	// 0x006ACFA0
	if ( MH_CreateHook( pattern_EnumerateContent.get_first(), &ContentManager_EnumerateContent, NULL ) != MH_OK )
		return;

	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
		return;

	// 0x006ACE00
	ContentManager_UpdatePartDB = (UPDATEPARTDBFUNC)pattern_UpdatePartDB.get_first();
}

void *( WINAPI *Direct3DCreate9_orig )( UINT ) = NULL;
void *Direct3DCreate9_target = NULL;

void *WINAPI Direct3DCreate9_hook( UINT SDKVersion )
{
	void *result = Direct3DCreate9_orig( SDKVersion );

	Initialize();

	return result;
}

extern "C" __declspec( dllexport ) void InitializeASI()
{
	// Most game exes have SecuROM so we can't insert our hooks just yet.
	// Create an early hook that lets us know when the game code has finished unpacking.
	MH_Initialize();
	MH_CreateHookApiEx( L"d3d9", "Direct3DCreate9", &Direct3DCreate9_hook, (void **)&Direct3DCreate9_orig, &Direct3DCreate9_target );
	MH_EnableHook( Direct3DCreate9_target );
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/ )
{
	switch ( fdwReason )
	{
		case DLL_PROCESS_ATTACH:
			g_module = hinstDLL;
			break;
		case DLL_THREAD_ATTACH:
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_DETACH:
		default:
			break;
	}
	return TRUE;
}
