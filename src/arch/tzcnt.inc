/*
Count trailing zero bits. Choice of public domain or MIT-0.

David Reid - mackron@gmail.com

The tzcnt32 and tzcnt64 functions count the number of trailing zero bits in a given 32- or 64-bit variable. When the input variable is 0, the
total size in bits will be returned (32 for tzcnt32 and 64 for tzcnt64).

For x86/64 platforms, this will use the TZCNT instruction if available. On ARM it will be implemented in terms of the CLZ instruction. If these
are unavailable it will fall back to compiler-specific built-ins. If these are unavailable it'll fall back to the generic implementation.


License
=======

Public Domain (www.unlicense.org)
-------------------------------------------------
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>


Functions
---------
tzcnt32_generic
tzcnt64_generic
    Generic implementation.

tzcnt32_msvc_bsf
tzcnt64_msvc_bsf
    MSVC built-in implementation using _BitScanForward/64(). Note that tzcnt64_mscv_bsf() is only available when compiling as 64-bit.

tzcnt32_gcc_builtin
tzcnt64_gcc_builtin
    GCC/Clang built-in implementation using __builtin_ctzl/l(). Note that tzcnt64_gcc_builtin() is only available when compiling as 64-bit.

tzcnt32_msvc_x86
tzcnt64_msvc_x64
    MSVC implementation in terms of the __lzcnt and __lzcnt64 intrinsic. Note that these are only available when targeting x86/64. tzcnt64_msvc_x64()
    is only available when compiling as 64-bit.

tzcnt32_gcc_x86
tzcnt64_gcc_x64
    GCC/Clang inline assembly implementation. This will emit the TZCNT instruction. Note that these are only available when targeting x86/x64
    and when compiled using a compiler that supports GCC style inline assembly.

tzcnt32_gcc_arm
tzcnt64_gcc_arm
    GCC/Clang inline assembly implementation. This will be implemented in terms of the CLZ instruction. Note that these are only available when
    targeting ARM architecture version 5 and above and when compiled using a compiler that supports GCC style inline assembly.

tzcnt32_hard
tzcnt64_hard
    High level helper for calling an hardware implementation. This will choose either tzcnt32_msvc_x86()/tzcnt64_msvc_x64() or tzcnt32_gcc_x86()/
    tzcnt64_gcc_x64() depending on the environment. Note that this is only available when targeting x86/64. tzcnt64_hard() is only available
    when compiling as 64-bit. You should only call this if has_tzcnt_hard() returns non-zero.

tzcnt32_soft
tzcnt64_soft
    High level helper for calling the best software implementation available for the current build environment.

tzcnt32
tzcnt64
    High level helper for calling either a hardware or software implementation depending on the build environment. This will always favor a
    hardware implementation. Do not call this in high performance code. The reason for this is that each it will call has_tzcnt_hard() each
    time which may be too fine grained for your purposes. You may be better off calling has_tzcnt_hard() once at a higher level.

has_tzcnt_hard
    Determines whether or not a hardware implementation of tzcnt is available. Use this to know whether or not you can call tzcnt32/64_hard().
    Note that this calls CPUID for each, so you may want to cache the result. Use HAS_TZCNT32/64_HARD to check for compile-time support.
*/
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#if defined(__i386) || defined(_M_IX86)
    #define ARCH_X86
#elif defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X64
#elif (defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 5) || (defined(_M_ARM) && _M_ARM >= 5) || defined(__ARM_FEATURE_CLZ) /* ARM (Architecture Version 5) */
    #define ARCH_ARM
#endif

#if defined(_WIN64) || defined(_LP64) || defined(__LP64__)
    #define ARCH_64BIT
#else
    #define ARCH_32BIT
#endif

#if defined(ARCH_X86) || defined(ARCH_X64)
    /* x86/64 */
    #if defined(_MSC_VER) && _MSC_VER >= 1500
        #define HAS_TZCNT32_HARD
        #if defined(ARCH_64BIT)
            #define HAS_TZCNT64_HARD
        #endif
    #elif defined(__GNUC__) || defined(__clang__)
        #define HAS_TZCNT32_HARD
        #if defined(ARCH_64BIT)
            #define HAS_TZCNT64_HARD
        #endif
    #endif
#elif defined(ARCH_ARM)
    /* ARM */
    #if defined(__GNUC__) || defined(__clang__)
        #define HAS_TZCNT32_HARD
        #if defined(ARCH_64BIT)
            #define HAS_TZCNT64_HARD
        #endif
    #endif
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1500 && (defined(ARCH_X86) || defined(ARCH_X64)) && !defined(__clang__)
    #define HAS_TZCNT_INTRINSIC
#elif (defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)))
    #define HAS_TZCNT_INTRINSIC
#elif defined(__clang__)
    #if defined(__has_builtin)
        #if __has_builtin(__builtin_ctzll) || __has_builtin(__builtin_ctzl)
            #define HAS_TZCNT_INTRINSIC
        #endif
    #endif
#endif

inline unsigned int tzcnt32_generic(unsigned int x)
{
    unsigned int n;

    /* Special case for odd numbers since they should happen about half the time. */
    if (x & 0x1)  {
        return 0;
    }

    if (x == 0) {
        return sizeof(x) << 3;
    }

    n = 1;
    if ((x & 0x0000FFFF) == 0) { x >>= 16; n += 16; }
    if ((x & 0x000000FF) == 0) { x >>=  8; n +=  8; }
    if ((x & 0x0000000F) == 0) { x >>=  4; n +=  4; }
    if ((x & 0x00000003) == 0) { x >>=  2; n +=  2; }
    n -= x & 0x00000001;

    return n;
}

inline unsigned int tzcnt64_generic(unsigned long long x)
{
    unsigned int n;

    /* Special case for odd numbers since they should happen about half the time. */
    if (x & 0x1)  {
        return 0;
    }

    if (x == 0) {
        return sizeof(x) << 3;
    }

    n = 1;
    if ((x & 0xFFFFFFFF) == 0) { x >>= 32; n += 32; }
    if ((x & 0x0000FFFF) == 0) { x >>= 16; n += 16; }
    if ((x & 0x000000FF) == 0) { x >>=  8; n +=  8; }
    if ((x & 0x0000000F) == 0) { x >>=  4; n +=  4; }
    if ((x & 0x00000003) == 0) { x >>=  2; n +=  2; }
    n -= x & 0x00000001;

    return n;
}

/* Generic compiler specific intrinsics. */
#if defined(_MSC_VER)
static unsigned int tzcnt32_msvc_bsf(unsigned int x)
{
    unsigned long n;

    if (x == 0) {
        return 32;
    }

    _BitScanForward(&n, x);

    return n;
}

/* _BitScanReverse64() is only available on 64-bit builds. */
#if defined(ARCH_64BIT)
static unsigned int tzcnt64_msvc_bsf(unsigned long long x)
{
    unsigned long n;

    if (x == 0) {
        return 64;
    }

    _BitScanForward64(&n, x);

    return n;
}
#endif  /* ARCH_64BIT */
#elif (defined(__GNUC__) || defined(__clang__)) && defined(HAS_TZCNT_INTRINSIC)
static unsigned int tzcnt32_gcc_builtin(unsigned int x)
{
    if (x == 0) {
        return 32;
    }

    return (unsigned int)__builtin_ctzl((unsigned long)x);
}

static unsigned int tzcnt64_gcc_builtin(unsigned long long x)
{
    if (x == 0) {
        return 64;
    }

    return (unsigned int)__builtin_ctzll(x);
}
#endif

static int has_tzcnt_hard()
{
#if defined(ARCH_X86) || defined(ARCH_X64)
    int info[4] = {0};

    #if defined(_MSC_VER)
        __cpuid(info, 0x80000001);
    #elif defined(__GNUC__) || defined(__clang__)
        /*
        It looks like the -fPIC option uses the ebx register which GCC complains about. We can work around this by just using a different register, the
        specific register of which I'm letting the compiler decide on. The "k" prefix is used to specify a 32-bit register. The {...} syntax is for
        supporting different assembly dialects.

        What's basically happening is that we're saving and restoring the ebx register manually.
        */
        #if defined(ARCH_X86) && defined(__PIC__)
            __asm__ __volatile__ (
                "xchg{l} {%%}ebx, %k1;"
                "cpuid;"
                "xchg{l} {%%}ebx, %k1;"
                : "=a"(info[0]), "=&r"(info[1]), "=c"(info[2]), "=d"(info[3]) : "a"(0x80000001), "c"(0)
            );
        #else
            __asm__ __volatile__ (
                "cpuid" : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3]) : "a"(0x80000001), "c"(0)
            );
        #endif
    #endif

    return (info[2] & (1 << 5)) != 0;
#elif defined(ARCH_ARM)
    return 1;   /* The CLZ instruction is available starting from ARM architecture version 5. Our ARCH_ARM #define is only defined when targeting version 5 at compile time. */
#else
    return 0;   /* Hardware TZCNT is only supported in x86/64 and ARM for now. */
#endif
}

/* Intrinsics and inline-assembly. x86/64 has a hardware TZCNT instruction. You can only call these if has_tzcnt_hard() returns true. */
#if defined(HAS_TZCNT32_HARD)
    #if defined(ARCH_X86) || defined(ARCH_X64)
        #if defined(_MSC_VER) && !defined(__clang__)
            /* Unfortunately no tzcnt instrinsic on MSVC, but we can build it in terms of lzcnt(). */
            static unsigned int tzcnt32_msvc_x86(unsigned int x)
            {
                if (x == 0) {
                    return sizeof(x) << 3;
                }

                return 31 - __lzcnt(x & -(int)x);
            }
        #elif defined(__GNUC__) || defined(__clang__)
            static unsigned int tzcnt32_gcc_x86(unsigned int x)
            {
                /*
                att:   tzcntl [out], [in]
                intel: tzcnt  [in], [out]
                */
                unsigned int r;
                __asm__ __volatile__ (
                    "tzcnt{l %1, %0| %0, %1}" : "=r"(r) : "r"(x) : "cc"
                );

                return r;
            }
        #endif
    #endif
    #if defined(ARCH_ARM)
        #if defined(__GNUC__) || defined(__clang__)
            /* The ARM implementation needs to be written in terms of the CLZ instruction. This can probably be optimized by implementing the whole function in assembly. */
            static unsigned int tzcnt32_gcc_arm(unsigned int x)
            {
                unsigned int r;

                if (x == 0) {
                    return sizeof(x) << 3;
                }

                __asm__ __volatile__ (
                #if defined(ARCH_32BIT)
                    "clz %[out], %[in]" : [out]"=r"(r) : [in]"r"(x)
                #else
                    "clz %w[out], %w[in]" : [out]"=r"(r) : [in]"r"(x)
                #endif
                );
                
                return 31 - r;
            }
        #endif
    #endif

    static unsigned int tzcnt32_hard(unsigned int x)
    {
        #if defined(ARCH_X86) || defined(ARCH_X64)
            #if defined(_MSC_VER) && !defined(__clang__)
                return tzcnt32_msvc_x86(x);
            #elif defined(__GNUC__) || defined(__clang__)
                return tzcnt32_gcc_x86(x);
            #else
                #error "This compiler does not support the tzcnt intrinsic."
            #endif
        #elif defined(ARCH_ARM)
            #if defined(__GNUC__) || defined(__clang__)
                return tzcnt32_gcc_arm(x);
            #else
                #error "This compiler does not support the clz intrinsic."
            #endif
        #else
            #error "The build target does not support a native instruction."
        #endif
    }
#endif

#if defined(HAS_TZCNT64_HARD)
    #if defined(ARCH_X86) || defined(ARCH_X64)
        #if defined(_MSC_VER) && !defined(__clang__)
            static unsigned int tzcnt64_msvc_x64(unsigned long long x)
            {
                return _tzcnt_u64(x);
            }
        #elif defined(__GNUC__) || defined(__clang__)
            static unsigned int tzcnt64_gcc_x64(unsigned long long x)
            {
                /*
                att:   tzcnt [out], [in]
                intel: tzcnt [in], [out]
                */
                unsigned long long r;
                __asm__ __volatile__ (
                    "tzcnt{ %1, %0| %0, %1}" : "=r"(r) : "r"(x) : "cc"
                );

                return r;
            }
        #endif
    #endif
    #if defined(ARCH_ARM)
        #if defined(__GNUC__) || defined(__clang__)
            static unsigned int tzcnt64_gcc_arm(unsigned long long x)
            {
				return __builtin_ctzl(x);
            }
        #endif
    #endif

    static unsigned int tzcnt64_hard(unsigned long long x)
    {
    #if defined(ARCH_X64)
        #if defined(_MSC_VER) && !defined(__clang__)
            return tzcnt64_msvc_x64(x);
        #elif defined(__GNUC__) || defined(__clang__)
            return tzcnt64_gcc_x64(x);
        #else
            #error "This compiler does not support the tzcnt intrinsic."
        #endif
    #elif defined(ARCH_ARM) && defined(ARCH_64BIT)
        #if defined(__GNUC__) || defined(__clang__)
            return tzcnt64_gcc_arm(x);
        #else
            #error "This compiler does not support the clz intrinsic."
        #endif
    #else
        #error "The build target does not support a native instruction."
    #endif
    }
#endif


static unsigned int tzcnt32_soft(unsigned int x)
{
#if defined(_MSC_VER)
    return tzcnt32_msvc_bsf(x);
#elif defined(HAS_TZCNT_INTRINSIC)
    return tzcnt32_gcc_builtin(x);
#else
    return tzcnt32_generic(x);
#endif
}

static unsigned int tzcnt64_soft(unsigned long long x)
{
#if defined(ARCH_64BIT)
    #if defined(_MSC_VER)
        return tzcnt64_msvc_bsf(x);
    #elif defined(HAS_TZCNT_INTRINSIC)
        return tzcnt64_gcc_builtin(x);
    #else
        return tzcnt64_generic(x);
    #endif
#else
    return tzcnt64_generic(x);
#endif
}


inline static unsigned int tzcnt32(unsigned int x)
{
#if defined(HAS_TZCNT32_HARD)
    if (has_tzcnt_hard()) {
        return tzcnt32_hard(x);
    } else
#endif
    {
        return tzcnt32_soft(x);
    }
}

inline static unsigned int tzcnt64(unsigned int x)
{
#if defined(HAS_TZCNT64_HARD)
    if (has_tzcnt_hard()) {
        return tzcnt64_hard(x);
    } else
#endif
    {
        return tzcnt64_soft(x);
    }
}
