# m68k-amigaos cross toolchain (bebbo's amiga-gcc, GCC 16).  Point AMIGA_TOOLCHAIN_ROOT
# at the prefix holding bin/m68k-amigaos-gcc, or have it on the PATH.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR m68k)
if(DEFINED ENV{AMIGA_TOOLCHAIN_ROOT})
    set(_root "$ENV{AMIGA_TOOLCHAIN_ROOT}/bin/")
else()
    set(_root "")
endif()
set(CMAKE_C_COMPILER   ${_root}m68k-amigaos-gcc)
set(CMAKE_ASM_COMPILER ${_root}m68k-amigaos-gcc)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_C_FLAGS_INIT "-noixemul")
