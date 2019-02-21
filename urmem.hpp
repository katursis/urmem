#ifndef URMEM_H_
#define URMEM_H_

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <vector>
#include <iterator>
#include <algorithm>
#include <memory>
#include <mutex>

class urmem {
public:
    using address_t = unsigned long;
    using byte_t = unsigned char;
    using bytearray_t = std::vector<byte_t>;

    enum class calling_convention {
        cdeclcall,
        stdcall,
        thiscall
    };

    template<calling_convention CConv = calling_convention::cdeclcall, typename Ret = void, typename ... Args>
    static Ret call_function(address_t address, Args ... args) {
#ifdef _WIN32
        return invoker<CConv>::call<Ret, Args...>(address, args...);
#else
        return (reinterpret_cast<Ret(*)(Args...)>(address))(args...);
#endif
    }

    template<typename T>
    static address_t get_func_addr(T func) {
        union {
            T func;
            address_t addr;
        } u{func};

        return u.addr;
    };

    static void unprotect_memory(address_t addr, std::size_t length) {
#ifdef _WIN32
        unsigned long original_protect{};

        VirtualProtect(reinterpret_cast<void *>(addr), length, PAGE_EXECUTE_READWRITE, &original_protect);
#else
        addr = addr & ~(sysconf(_SC_PAGE_SIZE) - 1);

        mprotect(reinterpret_cast<void *>(addr), length, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
    }

    class pointer {
    public:
        pointer() = delete;

        pointer(address_t address) : _pointer(address) {}

        template<typename T>
        T &field(std::size_t offset) {
            return *reinterpret_cast<T *>(_pointer + offset);
        }

        pointer ptr_field(std::size_t offset) {
            return pointer(field<address_t>(offset));
        }

        template<typename T>
        operator T *() const {
            return reinterpret_cast<T *>(_pointer);
        }

    private:
        const address_t _pointer;
    };

    class unprotect_scope {
    public:
        unprotect_scope() = delete;
        unprotect_scope(address_t addr, std::size_t length) :_addr(addr), _length(length) {
#ifdef _WIN32
            VirtualProtect(reinterpret_cast<void *>(_addr), _length, PAGE_EXECUTE_READWRITE, &_original_protect);
#else
            _addr = _addr & ~(sysconf(_SC_PAGE_SIZE) - 1);

            mprotect(reinterpret_cast<void *>(_addr), _length, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
        }

        ~unprotect_scope() {
#ifdef _WIN32
            VirtualProtect(reinterpret_cast<void *>(_addr), _length, _original_protect, nullptr);
#else
            mprotect(reinterpret_cast<void *>(_addr), _length, PROT_READ | PROT_EXEC);
#endif
        }

    private:
#ifdef _WIN32
        unsigned long _original_protect;
#endif
        address_t _addr;
        const std::size_t _length;
    };

    class sig_scanner {
    public:
        bool init(address_t addr_in_module) {
#ifdef _WIN32
            MEMORY_BASIC_INFORMATION info{};
            if (!VirtualQuery(reinterpret_cast<void *>(addr_in_module), &info, sizeof(info))) {
                return false;
            }

            auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(info.AllocationBase);
            auto pe = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<address_t>(dos) + dos->e_lfanew);

            if (pe->Signature != IMAGE_NT_SIGNATURE) {
                return false;
            }

            _base = reinterpret_cast<address_t>(info.AllocationBase);
            _size = pe->OptionalHeader.SizeOfImage;
#else
            Dl_info info{};
            struct stat buf{};

            if (!dladdr(reinterpret_cast<void *>(addr_in_module), &info)) {
                return false;
            }

            if (stat(info.dli_fname, &buf) != 0) {
                return false;
            }

            _base = reinterpret_cast<address_t>(info.dli_fbase);
            _size = buf.st_size;
#endif
            return true;
        }

        bool find(const char *pattern, const char *mask, address_t &addr) const {
            auto current_byte = reinterpret_cast<byte_t *>(_base);
            auto last_byte = current_byte + _size;

            std::size_t i{};
            while (current_byte < last_byte) {
                for (i = 0; mask[i]; ++i) {
                    if (&current_byte[i] >= last_byte ||
                        ((mask[i] != '?') && (static_cast<byte_t>(pattern[i]) != current_byte[i]))) {
                        break;
                    }
                }

                if (!mask[i]) {
                    addr = reinterpret_cast<address_t>(current_byte);

                    return true;
                }

                ++current_byte;
            }

            return false;
        }

    private:
        address_t _base{};
        std::size_t _size{};
    };

    class patch {
    public:
        patch() = delete;

        patch(address_t addr, const bytearray_t &new_data)
            : _patch_addr(addr), _new_data(new_data), _original_data(new_data.size(), 0x90), _enabled(false) {
            unprotect_memory(_patch_addr, _new_data.size());

            enable();
        }

        ~patch() {
            disable();
        }

        void enable() {
            if (_enabled) {
                return;
            }

            std::copy_n(
                reinterpret_cast<bytearray_t::value_type *>(_patch_addr),
                _new_data.size(),
                _original_data.data()
            );

            std::copy_n(
                _new_data.data(),
                _new_data.size(),
                reinterpret_cast<bytearray_t::value_type *>(_patch_addr)
            );

            _enabled = true;
        }

        void disable() {
            if (!_enabled) {
                return;
            }

            std::copy_n(
                _original_data.data(),
                _original_data.size(),
                reinterpret_cast<bytearray_t::value_type *>(_patch_addr)
            );

            _enabled = false;
        }

        bool is_enabled() const {
            return _enabled;
        }

    private:
        address_t _patch_addr;
        bytearray_t _original_data;
        bytearray_t _new_data;
        bool _enabled;
    };

    class hook {
    public:
        enum class type {
            jmp,
            call
        };

        class raii {
        public:
            raii() = delete;

            raii(hook &h) : _hook(h) {
                _hook.disable();
            }

            ~raii() {
                _hook.enable();
            }

        private:
            hook &_hook;
        };

        hook() = default;

        hook(address_t inject_addr, address_t handle_addr, hook::type h_type = hook::type::jmp, std::size_t length = 5) {
            install(inject_addr, handle_addr, h_type, length);
        }

        void install(address_t inject_addr, address_t handle_addr, hook::type h_type = hook::type::jmp, std::size_t length = 5) {
            bytearray_t new_bytes(length, 0x90);

            switch (h_type) {
                case type::jmp:
                {
                    new_bytes[0] = 0xE9;
                    _original_addr = inject_addr;

                    break;
                }
                case type::call:
                {
                    new_bytes[0] = 0xE8;
                    _original_addr = pointer(inject_addr).field<address_t>(1) + (inject_addr + 5);

                    break;
                }
            }

            *reinterpret_cast<address_t *>(&new_bytes[1]) = handle_addr - (inject_addr + 5);

            _patch = std::make_shared<patch>(inject_addr, new_bytes);
        }

        void enable() {
            _patch->enable();
        }

        void disable() {
            _patch->disable();
        }

        bool is_enabled() const {
            return _patch->is_enabled();
        }

        address_t get_original_addr() const {
            return _original_addr;
        }

        template<calling_convention CConv = calling_convention::cdeclcall, typename Ret = void, typename ... Args>
        Ret call(Args ... args) {
            raii scope(*this);

            return call_function<CConv, Ret, Args...>(_original_addr, args...);
        }

    private:
        address_t _original_addr{};
        std::shared_ptr<patch> _patch;
    };

private:
#ifdef _WIN32
    template<calling_convention>
    struct invoker;

    template<>
    struct invoker<calling_convention::cdeclcall> {
        template<typename Ret, typename ... Args>
        static inline Ret call(address_t address, Args ... args) {
            return (reinterpret_cast<Ret(__cdecl *)(Args...)>(address))(args...);
        }
    };

    template<>
    struct invoker<calling_convention::stdcall> {
        template<typename Ret, typename ... Args>
        static inline Ret call(address_t address, Args ... args) {
            return (reinterpret_cast<Ret(__stdcall *)(Args...)>(address))(args...);
        }
    };

    template<>
    struct invoker<calling_convention::thiscall> {
        template<typename Ret, typename ... Args>
        static inline Ret call(address_t address, Args ... args) {
            return (reinterpret_cast<Ret(__thiscall *)(Args...)>(address))(args...);
        }
    };
#endif
};

#endif // URMEM_H_
