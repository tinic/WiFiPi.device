cmake_minimum_required(VERSION 3.14.0)
project(WiFiPi VERSION 0.4.0)

include(cmake/verstring.cmake)
get_verstring(VERSTRING)

if(NOT TARGET devicetree)
    add_subdirectory(devicetree.resource EXCLUDE_FROM_ALL)
endif()

add_executable(wifipi.device
    src/start.c
    src/device.c
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
    -flto -fno-fat-lto-objects)
target_compile_definitions(wifipi.device PRIVATE VERSION_STRING="${VERSTRING}")
target_link_options(wifipi.device PRIVATE -s -ffreestanding -nostdlib -nostartfiles -Wl,-e,__start
    -Os -m68040 -flto -fuse-linker-plugin)
target_link_libraries(wifipi.device devicetree amiga)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wifipi.device DESTINATION Emu68-WiFi/Devs/Networks)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/firmware/ DESTINATION Emu68-WiFi/Devs/Firmware)
