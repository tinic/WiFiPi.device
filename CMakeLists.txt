cmake_minimum_required(VERSION 3.14.0)
project(WiFiPi VERSION 0.4.0)

include(cmake/verstring.cmake)
get_verstring(VERSTRING)

if(NOT TARGET devicetree)
    add_subdirectory(devicetree.resource EXCLUDE_FROM_ALL)
endif()

add_executable(wifipi.device
    src/device.c        # keep first: the entry stub and the ROMTag
    src/init.c
    src/mbox.c
    src/sdio.c
    src/end.c
    src/wifipi.c
    src/packet.c
    src/d11.c
    src/unit.c
    src/findtoken.c
)

target_include_directories(wifipi.device PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
# -fno-tree-loop-distribute-patterns and -fno-builtin: a freestanding image has no
# libc for the memset/memcpy calls GCC would otherwise invent; the loops stay loops.
target_compile_options(wifipi.device PRIVATE -Os -m68040 -Wall -Wextra -Werror -fomit-frame-pointer
    -ffreestanding -fno-builtin -fno-tree-loop-distribute-patterns
    -flto)
target_compile_definitions(wifipi.device PRIVATE VERSION_STRING="${VERSTRING}")
# -Wl,-u,_RomTag: nothing in the image references the ROMTag (exec finds it by
# scanning for RTC_MATCHWORD), so under LTO the linker plugin sees it, the init
# table, the LVO vector table and every function they point at as dead code
# and drops them.  Naming it as a link root holds the whole chain; RomTag's
# __attribute__((used)) is the second, independent hold (measured: with either
# one alone the image is whole, with neither this ld dies in the LTO link).
# ld accepts a misspelled -u name silently, so tools/check-image.sh proves the
# ROMTag chain in the bytes of every image after the link.
target_link_options(wifipi.device PRIVATE -s -ffreestanding -nostdlib -nostartfiles -Wl,-e,__start
    -Os -m68040 -flto -fuse-linker-plugin
    -Wl,-u,_RomTag -Wl,-Map,${CMAKE_CURRENT_BINARY_DIR}/wifipi.device.map)
add_custom_command(TARGET wifipi.device POST_BUILD
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-image.sh
            $<TARGET_FILE:wifipi.device> ${CMAKE_CURRENT_BINARY_DIR}/wifipi.device.map wifipi.device
    COMMENT "Checking the image survived LTO whole")
target_link_libraries(wifipi.device devicetree amiga)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wifipi.device DESTINATION Emu68-WiFi/Devs/Networks)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/firmware/ DESTINATION Emu68-WiFi/Devs/Firmware)
