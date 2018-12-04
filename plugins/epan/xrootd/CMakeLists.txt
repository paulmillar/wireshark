
include(WiresharkPlugin)

set_module_info(xrootd 0 0 1 0)

set(DISSECTOR_SRC
        packet-xrootd.c
)

set(PLUGIN_FILES
        plugin.c
        ${DISSECTOR_SRC}
)


set_source_files_properties(
        ${PLUGIN_FILES}
        PROPERTIES
        COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
        plugin
        ${DISSECTOR_SRC}
)

add_plugin_library(xrootd epan)

target_link_libraries(xrootd epan)

install_plugin(xrootd epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
        NAME
          xrootd
        SWITCHES
          -g abort -g termoutput -build
        SOURCES
          ${DISSECTOR_SRC}
          ${DISSECTOR_HEADERS}
)
