#include <iostream>
#include "urmem.hpp"

#ifdef _WIN32
#pragma optimize("", off)
#endif

using namespace std;

#ifdef _WIN32
_declspec(noinline) int __cdecl sum(int a, int b)
#else
int sum(int a, int b)
#endif
{
	return a + b;
}

class adder {
public:
	adder(int a) : _a(a) {};
#ifdef _WIN32
	_declspec(noinline) int sum(int b)
#else
	int sum(int b)
#endif
	{
		return _a + b;
	}
private:
	int _a{};
};

enum e_hook {
	h_sum,
	h_adder_sum,
	h_message_box
};

int main(void) {
	/*Function*/

	urmem::smart_hook<
		e_hook::h_sum, // unique hook's id
		urmem::calling_convention::cdeclcall, // calling convention
		int(int, int)> // signature
		hook_sum(urmem::get_func_addr(&sum));

	hook_sum.attach([&hook_sum](int a, int b) {
		return hook_sum.call(a, b) * 2; // will double the result
	});

	cout << sum(2, 3) << endl; // will print '10'

	/*Class method*/

	adder adder_obj(10);

	urmem::smart_hook<e_hook::h_adder_sum, urmem::calling_convention::thiscall, int(void *, int)>
		hook_adder_sum(urmem::get_func_addr(&adder::sum));

	hook_adder_sum.attach([&hook_adder_sum](void *_this, int b) {
		return hook_adder_sum.call(_this, b) * 10;
	});

	cout << adder_obj.sum(10) << endl; // will print '200'

#ifdef _WIN32	
	/*WinAPI function*/

	auto addr = GetProcAddress(GetModuleHandleA("User32.dll"), "MessageBoxA");

	urmem::smart_hook<e_hook::h_message_box, urmem::calling_convention::stdcall,
		int(HWND, LPCSTR, LPCSTR, UINT)> hook_message_box(addr);

	hook_message_box.attach([&hook_message_box](HWND wnd, LPCSTR text, LPCSTR caption, UINT type) {
		return hook_message_box.call(wnd, "Hello, urmem!", "Author: urShadow", type);
	});

	MessageBoxA(0, "Hello, World!", "Caption", MB_OK);
#endif
}
