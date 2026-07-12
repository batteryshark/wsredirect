#pragma once

BOOL iat_hook(HMODULE dll, char const* targetDLL, void* targetFunction, void* detourFunction);
BOOL ezHook(HMODULE hostDll, void* originalFunction, char* forwardFunctionEntry);