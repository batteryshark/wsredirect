#include <winsock2.h>
#include <Windows.h>
#include "ws2tcpip.h"

#include "win32_hook.h"
#include "cJSON.h"

#pragma comment(lib, "ws2_32.lib")

// Our Global Redirect Config
static cJSON* config = NULL;

// Generic, load a text file stuff.
BOOL LoadTextData(const char* path, char** buffer) {
    HANDLE hFile = CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(!hFile){return FALSE;}
    DWORD length = 0;
    GetFileSize(hFile,&length);
    *buffer = (char*)malloc(length+1);
    if (!*buffer) { CloseHandle(hFile); return FALSE; }   
    ReadFile(hFile,*buffer,length,NULL,NULL);
    CloseHandle(hFile);
    return TRUE;

}

// Check for an entry match and redirect if so.
int x_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA * pHints, PADDRINFOA * ppResult)
{

	if (!config) {
		return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
	}

	// Combine Node and Service Name for Search
	int clength = strlen(pNodeName) + strlen(pServiceName) + 2;
	char* sname = (char*)calloc(1, clength);
    if (sname == NULL) {
        return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }
	strcat_s(sname,clength,pNodeName);
	strcat_s(sname,clength,":");
    strcat_s(sname, clength, pServiceName);
   
    cJSON* entry = cJSON_GetObjectItem(config, sname);
    if (!entry) {
        return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }
    *ppResult = calloc(1, sizeof(struct addrinfo));
    if (*ppResult == NULL) {
        return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    char* redirected_host = cJSON_GetObjectItemCaseSensitive(entry, "host")->valuestring;
    char* redirected_port = cJSON_GetObjectItemCaseSensitive(entry, "port")->valuestring;
    // We may have to resolve an ip from a hostname
    if (!redirected_host || !strlen(redirected_host)) {
        redirected_host = cJSON_GetObjectItemCaseSensitive(entry, "ip")->valuestring;
    }

    return getaddrinfo(redirected_host, redirected_port, pHints, ppResult);

}


void init_wsr() {
    // Load Redirect Configuration
    char* cdata = NULL;
    LoadTextData("wsr.config", &cdata);
    config = cJSON_Parse(cdata);
    // Hook getaddrinfo
    iat_hook(GetModuleHandleA(NULL), "WS2_32.DLL", GetProcAddress(GetModuleHandleA("ws2_32.dll"), "getaddrinfo"), x_getaddrinfo);
}

// Entry-Point Function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch(fdwReason){
        case DLL_PROCESS_ATTACH:
            init_wsr();
        case DLL_PROCESS_DETACH:
            break;

    }
    return TRUE;
}

// Piggyback Function
void __declspec(dllexport) wsr(void) {}
