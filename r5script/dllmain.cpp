#include <cstdio>
#include <thread>
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

#include "skcrypter.h"
#include "lazy_importer.hh"
#include "detours.h"

typedef wchar_t SQChar;
typedef __int64 SQInteger;
typedef unsigned __int64 SQUnsignedInteger;
typedef SQUnsignedInteger SQBool;

typedef SQInteger(__fastcall* load_rson_fn)(const SQChar*);
typedef SQBool(__fastcall* load_script_fn)(void*, const SQChar*, const SQChar*, SQInteger);

SQInteger __fastcall load_rson(const SQChar*);
load_rson_fn original_load_rson = nullptr;

SQBool __fastcall load_script(void*, const SQChar*, const SQChar*, SQInteger);
load_script_fn original_load_script = nullptr;

SQInteger __fastcall load_rson(const SQChar* rsonfile)
{
	std::string file = std::string(skCrypt("custom/")) + std::string(reinterpret_cast<const char*>(rsonfile));
	std::ifstream file_stream(file);

	if (file_stream.good()) {

		const std::string content((std::istreambuf_iterator<char>(file_stream)), (std::istreambuf_iterator<char>()));
		printf(skCrypt("loading : %s\n"), file.c_str());

		return original_load_rson(reinterpret_cast<const SQChar*>(file.c_str()));
	}
	else
	{
		return original_load_rson(rsonfile);
	}
}

SQBool load_script(void* sqvm, const SQChar* szScriptPath, const SQChar* szScriptName, SQInteger nFlag)
{
	std::string file = std::string(skCrypt("custom/")) + std::string(reinterpret_cast<const char*>(szScriptPath));
	std::ifstream file_stream(file);

	if ( file_stream.good()) {

		const std::string content( ( std::istreambuf_iterator<char>( file_stream ) ), ( std::istreambuf_iterator<char>( ) ) );
		printf(skCrypt("loading : %s\n"), file.c_str());

		return original_load_script(sqvm, reinterpret_cast<const SQChar*>(file.c_str()), szScriptName, nFlag);
	}
	else
	{
		return original_load_script(sqvm, szScriptPath, szScriptName, nFlag);
	}
}

uint8_t* find_pattern(const char* signature, const char* module_name) {
	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<int>{ };
		auto* const start = const_cast<char*>(pattern);
		const auto* const end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto* current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	auto* const module = LI_FN(GetModuleHandleA).cached()(module_name);
	auto* const dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	if (!dos_headers)
		return nullptr;

	auto* const nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(module) + dos_headers->e_lfanew);

	auto pattern_bytes = pattern_to_byte(signature);
	auto* const scan_bytes = reinterpret_cast<std::uint8_t*>(module);

	const auto s = pattern_bytes.size();
	auto* const d = pattern_bytes.data();

	for (auto i = 0ul; i < nt_headers->OptionalHeader.SizeOfImage - s; ++i) {
		auto found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scan_bytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scan_bytes[i];
		}
	}
	return nullptr;
}

bool __stdcall DllMain(const HMODULE module, const DWORD reason, LPVOID)
{
	if (reason != reason)
		return false;

	AllocConsole();
	FILE* fp;
	freopen_s(&fp, skCrypt("CONOUT$"), skCrypt("w"), stdout);
	freopen_s(&fp, skCrypt("CONOUT$"), skCrypt("w"), stderr);

	DetourTransactionBegin();

	original_load_rson = reinterpret_cast<SQInteger(*)(const SQChar*)>(find_pattern(skCrypt("4C 8B DC 49 89 5B 08 57 48 81 EC A0 00 00 00 33"), nullptr));
	original_load_script = reinterpret_cast<SQBool(*)(void*, const SQChar*, const SQChar*, SQInteger)>(find_pattern(skCrypt("48 8B C4 4C 89 40 18 55 41"), nullptr));

	DetourAttach((LPVOID*)&original_load_rson, &load_rson);
	DetourAttach((LPVOID*)&original_load_script, &load_script);

	DetourTransactionCommit();

	return true;
}