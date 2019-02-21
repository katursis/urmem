# urmem
C++11 cross-platform library for working with memory (hooks, patches, pointer's wrapper, signature scanner etc.)
## Simple example
```cpp
#include <iostream>
#include "urmem.hpp"

#ifdef _WIN32
#pragma optimize("", off)
#endif

#ifdef _WIN32
_declspec(noinline)
#endif
int
#ifdef _WIN32
__cdecl
#endif
Sum(int a, int b) {
    return a + b;
}

urmem::hook hook_sum;

int MySum(int a, int b) {
    return hook_sum.call<urmem::calling_convention::cdeclcall, int>(a, b) * 2;
}

int main() {
    hook_sum.install(urmem::get_func_addr(&Sum), urmem::get_func_addr(&MySum));

    std::cout << Sum(2, 3) << std::endl; // will print '10'

    return 1;
}
```
## TODO
- x64 support
- More helper functions
