# urmem
C++11 cross-platform library for working with memory (hooks, patches, pointer's wrapper, signature scanner etc.)
## Simple example
```cpp
#include <iostream>
#include "urmem.hpp"

#ifdef _WIN32
#pragma optimize("", off)
#endif

using namespace std;
using m = urmem;

#ifdef _WIN32
_declspec(noinline) int __cdecl sum(int a, int b)
#else
int sum(int a, int b)
#endif
{
	return a + b;
}

enum e_hook
{
	h_sum
};

int main(void)
{
	m::smart_hook<e_hook::h_sum, m::calling_convention::cdeclcall, int(int, int)> hook_sum(m::get_func_addr(&sum));

	hook_sum.attach([&hook_sum](int a, int b)
	{
		return hook_sum.call(a, b) * 2;
	});

	cout << sum(2, 3) << endl; // will print '10'	
}
```
## TODO
- x64 support
- More helper functions
