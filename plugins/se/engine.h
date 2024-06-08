// Copyright 2020-2023 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MUMBLE_PLUGIN_SE_ENGINE_
#define MUMBLE_MUMBLE_PLUGIN_SE_ENGINE_

// Logging
#include <iostream>

struct NetInfo {
	uint32_t type;
	uint8_t ip[4];
	uint16_t port;
};

using ptr_t = std::uint32_t;

struct CEngineClient {
	// Skipping 12 functions ptrs - Need to add 1 extra byte of padding at the start
	//  for it to align correctly, not sure why could just be skipping over the ptr or address
	//  for CEngineClient VTable ptr... idk
	ptr_t padding[12];
	// Virtual Function 12
	ptr_t GetLocalPlayer;
	ptr_t padding2[13];
	// Virtual Function 26
	ptr_t IsInGame;
	ptr_t padding3[45];
	// Virtual Function 72
	ptr_t GetNetChannelInfo;
};
struct CBaseClientState {
	ptr_t padding[36];
	// Virtual Function 36
	ptr_t SetSignonState;

	explicit operator bool() const {
		return SetSignonState;
	}
};


static CBaseClientState getLocalClient(const procptr_t engineClientPtr, const CEngineClient engineClient) {
	// We use GetBaseLocalClient() instead of GetLocalClient() because we just need the main client.
	// GetLocalClient() gets the client from an array at the index passed to the function.
	// There are multiple clients because of the split screen feature.

	const auto modules = proc->modules();

	auto iter = modules.find("engine.so");
	auto engineBaseAddress = iter->second.baseAddress();

	// TODO:
	//  74 for Left 4 Dead
	//  72 for GMOD
	//const auto GetNetChannelInfo = proc->virtualFunction(engineClientPtr, 72);
	const auto GetNetChannelInfoViaStruct = engineClient.GetNetChannelInfo;

	// Windows:
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 8B 40 ??          mov     eax, [eax+?]
	// C3                retn
	//
	// Linux:
	// 55                push    ebp
	// 89 E5             mov     ebp, esp
	// 83 EC 08          sub     esp, 8
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 8B 40 ??          mov     eax, [eax+?]
	// C9                leave
	// C3                retn

	// TODO:
	//  GMOD only
	// 0x86 or 0x87
	//const auto callTarget         = proc->peek< int32_t >(GetNetChannelInfoViaStruct + 2);
	//const auto callInstructionEnd = GetNetChannelInfoViaStruct + 6;
	//const auto GetBaseLocalClient = callInstructionEnd + callTarget;
	//std::printf("callTarget: 0x%X | callInstructionEnd: 0x%X\n", callTarget, callInstructionEnd);


//	const auto callTarget         = proc->peek< int32_t >(GetNetChannelInfo + (isWin32 ? 1 : 7));
//	const auto callInstructionEnd = GetNetChannelInfo + (isWin32 ? 5 : 11);
//	const auto GetBaseLocalClient = callInstructionEnd + callTarget;




	// Windows:
	// A1 ?? ?? ?? ??    mov     eax, dword_????????
	// 83 C0 ??          add     eax, ?
	// C3                retn
	//
	// Linux:
	// A1 ?? ?? ?? ??    mov     eax, dword_????????
	// 55                push    ebp
	// 89 E5             mov     ebp, esp
	// 5D                pop     ebp
	// 83 C0 ??          add     eax, ?
	// C3                retn

	// TODO: GMod only currently
	//auto iter = proc->modules().find("engine.so");
	//auto engineBaseAddress = iter->second.baseAddress();
	//std::printf("engine.so base address: 0x%X\n", engineBaseAddress);
	// TODO: KNOWN GOOD GMOD ADDRESS
	//auto address = engineBaseAddress + 0x00325060 + 1;
	//std::cout << "LocalBaseClient address: " << address << std::endl;

	//std::printf("GetBaseLocalClient RAW: 0x%X\n", GetBaseLocalClient);
	//std::printf("GetBaseLocalClient: 0x%X\n", GetBaseLocalClient - engineBaseAddress);

	const auto StartOfDatRef               = GetNetChannelInfoViaStruct + 2;
	const auto DatPtr                      = proc->peekPtr(StartOfDatRef);
	const auto ClientPtr                   = proc->peekPtr(engineBaseAddress + DatPtr);

	std::printf("StartOfDatReference: 0x%lX | DatPtr: 0x%lX | Client?: 0x%lX | Raw Client?: 0x%lX\n",
				StartOfDatRef - engineBaseAddress, DatPtr - engineBaseAddress, ClientPtr - engineBaseAddress,
				ClientPtr);

	if (!ClientPtr) {
		return {};
	}

	auto GetBaseLocalClient = proc->peek< CBaseClientState >(ClientPtr);

	//for (int i = 0; i < (sizeof(GetBaseLocalClient.padding)/sizeof(GetBaseLocalClient.padding[0])); ++i) {
	//	std::printf("CBaseClientState::Padding Pointers %d: 0x%X\n", i, GetBaseLocalClient.padding[i]);
	//}

	std::printf("CBaseClientState::SetSignonState: 0x%X\n", GetBaseLocalClient.SetSignonState);


	return GetBaseLocalClient;
	//return proc->peekPtr(address);
		   //+ proc->peek< int8_t >(address + 10);

	//return proc->peekPtr(proc->peek< uint32_t >(engineBaseAddress))
	//	   + proc->peek< int8_t >(engineBaseAddress + 10);
}

static int8_t getSignOnStateOffset(const procptr_t engineClient) {
	const auto IsInGame = proc->virtualFunction(engineClient, 26);
	std::printf("Is In Game address: %X\n", IsInGame);

	// Windows:
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 33 C9             xor     ecx, ecx
	// 83 78 ?? 06       cmp     dword ptr [eax+?], 6
	// 0F 94 C0          setz    al
	// C3                retn
	//
	// Linux:
	// 55                push    ebp
	// 89 E5             mov     ebp, esp
	// 83 EC 08          sub     esp, 8
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 83 78 ?? 06       cmp     dword ptr [eax+?], 6
	// C9                leave
	// 0F 94 C0          setz    al
	// C3                retn

	return proc->peek< int8_t >(IsInGame + 9);
	//return proc->peek< int8_t >(IsInGame + (isWin32 ? 9 : 13));
}

static int32_t getLevelNameOffset(const procptr_t engineClient) {
	const auto GetLevelNameShort = proc->virtualFunction(engineClient, 53);

	// Windows:
	// ...
	//
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 05 ?? ?? ?? ??    add     eax, ?
	// C3                retn
	//
	// Linux:
	// ...
	//
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 05 ?? ?? ?? ??    add     eax, ?
	// C9                leave
	// C3                retn
	if (isWin32) {
		if (proc->peek< uint8_t >(GetLevelNameShort + 37) == 0x05) {
			// Left 4 Dead
			return proc->peek< int32_t >(GetLevelNameShort + 38);
		} else {
			return proc->peek< int32_t >(GetLevelNameShort + 40);
		}
	}

	return proc->peek< int32_t >(GetLevelNameShort + 46);
}

static int32_t getNetInfoOffset(const procptr_t localClient, const procptr_t engineClient) {
	const auto GetNetChannelInfo = proc->virtualFunction(engineClient, 74);

	// Windows:
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 8B 40 ??          mov     eax, [eax+?]
	// C3                retn
	//
	// Linux:
	// 55                push    ebp
	// 89 E5             mov     ebp, esp
	// 83 EC 08          sub     esp, 8
	// E8 ?? ?? ?? ??    call    GetBaseLocalClient
	// 8B 40 ??          mov     eax, [eax+?]
	// C9                leave
	// C3                retn
	const auto NetChannelInfo =
		proc->peekPtr(localClient + proc->peek< int8_t >(GetNetChannelInfo + (isWin32 ? 7 : 13)));
	const auto GetAddress = proc->virtualFunction(NetChannelInfo, 1);

	// Windows:
	// 6A 00                      push    0
	// 81 C1 ?? ?? ?? ??          add     ecx, ?
	// E8 C3 9D 1D 00             call    ToString
	// C3                         retn
	//
	// Linux:
	// 55                         push    ebp
	// 89 E5                      mov     ebp, esp
	// 83 EC ??                   sub     esp, ?
	// 8B 45 08                   mov     eax, [ebp+arg_0]
	// C7 44 24 04 00 00 00 00    mov     dword ptr [esp+4], 0
	// 05 ?? ?? ?? ??             add     eax, ?
	// 89 04 24                   mov     [esp], eax
	// E8 ?? ?? ?? ??             call    ToString
	// C9                         leave
	// C3                         retn
	const auto netInfo = NetChannelInfo + proc->peek< int32_t >(GetAddress + (isWin32 ? 4 : 18));

	return static_cast< int32_t >(netInfo - localClient);
}

#endif
