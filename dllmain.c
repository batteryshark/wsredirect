#include <winsock2.h>
#include <Windows.h>

#include "cJSON.h"
#include "win32_hook.h"
#include "ws2tcpip.h"
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

// #define _DEBUG

void DBG_printf(const char* format, ...) {
#ifdef _DEBUG
    char s[8192];
    va_list args;
    memset(s, 0x00, 8192 * sizeof(s[0]));
    va_start(args, format);
    vsnprintf(s, 8191, format, args);
    va_end(args);
    s[8191] = 0;
    OutputDebugStringA(s);
#endif
}

// Generic, load a text file stuff.
BOOL LoadTextData(const char* path, char** buffer) {
    FILE* fp = NULL;
    fopen_s(&fp, path, "r");
    if (!fp) { return FALSE; }

    fseek(fp, 0L, SEEK_END);
    size_t length = ftell(fp);
    rewind(fp);
    *buffer = (char*)malloc(length);
    if (!*buffer) { return FALSE; }
    fread(*buffer, length, 1, fp);
    fclose(fp);
    return TRUE;

}

cJSON* config = NULL;
// getaddrinfo
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

    // Make the Necessary Adjustments
   // cJSON_Delete(entry);
    DBG_printf("Redirecting: %s -> %s:%s", sname, redirected_host, redirected_port);
    return getaddrinfo(redirected_host, redirected_port, pHints, ppResult);

}


void init_wsr() {
    char* cdata = NULL;
    LoadTextData("wsr.config", &cdata);
    config = cJSON_Parse(cdata);
}

// Entry-Point Function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        init_wsr();
        void* o_getaddrinfo_addr = GetProcAddress(GetModuleHandleA("ws2_32.dll"), "getaddrinfo");
        if (!iat_hook(GetModuleHandleA(NULL), "WS2_32.DLL", o_getaddrinfo_addr, x_getaddrinfo)) {
            DBG_printf("Failed to Hook GetAddrInfo");
            exit(-1);
        }
    }

    if (fdwReason == DLL_PROCESS_DETACH) {}
    return TRUE;

}


// Piggyback Function
void __declspec(dllexport) wsr(void) {}
