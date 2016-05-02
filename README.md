# urmem
C++11 crossplatform library for working with memory (hooks, patches, pointer's wrapper, signature scanner)
## Example
```cpp
#include "urmem.hpp"

using namespace std;
using namespace urmem;

shared_ptr<hook> hook_messageboxa;

int WINAPI HOOK_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	hook::context ctx(hook_messageboxa);

	lpText = "Hello, urmem!";

	return ctx.call_original<int>(calling_convention::stdcall, hWnd, lpText, lpCaption, uType);
}

void main(void)
{
	hook_messageboxa = hook::create(
		"messageboxa",
		reinterpret_cast<address_t>(GetProcAddress(GetModuleHandleA("User32.dll"), "MessageBoxA")),
		reinterpret_cast<address_t>(HOOK_MessageBoxA));

	MessageBoxA(0, "Hello, World!", "Test", 0);
}
```
