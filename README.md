# wsredirect

A small Windows DLL that redirects a process's network name/address lookups to
alternate hosts, IPs, and ports, driven by a JSON config. Inject it into a
target process and its Winsock name resolution is answered from a redirect
table instead of going out unchanged.

This is useful for pointing a legacy client at a replacement server, a local
stand-in, or a different port without editing the application or touching the
system `hosts` file. It is a proof of concept, not a general traffic proxy.

## How it works

`wsredirect` hooks Winsock name-resolution exports in the target process's
import/export tables (EAT-based hooking, see `win32_hook.c`). When the process
calls `getaddrinfo` (and the other wrapped lookup entry points), the hook looks
the requested `host` or `host:port` up in the loaded config:

- If the key matches, the lookup is rewritten to the configured `host`, `ip`,
  and/or `port`, then forwarded to the real Winsock function.
- If nothing matches, the original call is forwarded unchanged.

Redirects chain: a `host:port` entry can map to another host that itself has an
entry, so you can express both a name swap and the eventual IP/port in one file.

## Config

The redirect table is JSON, keyed by `host` or `host:port`. Empty fields are
left untouched.

```json
{
  "example.com:80": {
    "host": "replacement.example",
    "ip": "",
    "port": "12573"
  },
  "replacement.example": {
    "host": "",
    "ip": "203.0.113.32",
    "port": "80"
  }
}
```

See [`example/wsr.config`](example/wsr.config) for a complete sample.

## Build

Windows-only; links `ws2_32`. With MinGW-w64:

```sh
i686-w64-mingw32-gcc -shared -Wall -o wsredirect.dll dllmain.c win32_hook.c cJSON.c -lws2_32
x86_64-w64-mingw32-gcc -shared -Wall -o wsredirect.dll dllmain.c win32_hook.c cJSON.c -lws2_32
```

Then inject the built DLL into the target process by whatever means your setup
uses, with the config reachable at the path the loader expects.

## Status and limits

- Proof of concept. Only the lookup path is wrapped; it does not intercept
  connects, TLS, or raw socket addresses already in hand.
- Config path and load point are set up by the injecting host.
- Windows x86/x64 only.

## Credits

- EAT-based hooking in `win32_hook.c` is based on work by
  [ez (ezdiy)](https://github.com/ezdiy/).
- JSON parsing uses [cJSON](https://github.com/DaveGamble/cJSON) by Dave Gamble
  and contributors (MIT), vendored as `cJSON.c` / `cJSON.h`.
