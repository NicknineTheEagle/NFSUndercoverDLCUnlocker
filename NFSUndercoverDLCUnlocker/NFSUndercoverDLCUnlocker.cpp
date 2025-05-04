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

void __fastcall ContentManager_EnumerateContent( void *_this, void *_edx )
{
	std::vector<char> buf;
	for ( const std::string &dlc : g_dlcList )
	{
		buf.insert( buf.end(), dlc.begin(), dlc.end() );
		buf.insert( buf.end(), { '\r', '\n' } );
	}
	buf.push_back( '\0' );

	auto ContentManager_UpdatePartDB = (UPDATEPARTDBFUNC)0x6AD010;
	ContentManager_UpdatePartDB( _this, NULL, buf.size() - 1, buf.data(), NULL );
}

bool g_initialized = false;

void Initialize()
{
	if ( g_initialized )
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

	if ( MH_CreateHook( (LPVOID)0x6AD1B0, &ContentManager_EnumerateContent, NULL ) != MH_OK )
		return;

	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
		return;
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
	// Check if .exe file is compatible.
	uintptr_t base = (uintptr_t)GetModuleHandleA( NULL );
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)( base );
	IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)( base + dos->e_lfanew );

	if ( ( base + nt->OptionalHeader.AddressOfEntryPoint + ( 0x400000 - base ) ) != 0x87BA75 )
		return;

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
