cmake_minimum_required(VERSION 3.21)

project(DATUM VERSION 0.3.1 LANGUAGES C)
set(CMAKE_C_STANDARD 23)

include(GNUInstallDirs)

add_executable(datum_gateway
	src/datum_api.c
	src/datum_blocktemplates.c
	src/datum_coinbaser.c
	src/datum_conf.c
	src/datum_gateway.c
	src/datum_jsonrpc.c
	src/datum_logger.c
	src/datum_protocol.c
	src/datum_queue.c
	src/datum_sockets.c
	src/datum_stratum.c
	src/datum_stratum_dupes.c
	src/datum_submitblock.c
	src/datum_utils.c
	src/thirdparty_base58.c
	src/thirdparty_segwit_addr.c
	${CMAKE_CURRENT_BINARY_DIR}/web_resources.h
)
install(TARGETS datum_gateway DESTINATION bin)

set(WEB_RESOURCES
	www/auth_failed.html
	www/home.html
	www/clients_top.html
	www/coinbaser_top.html
	www/config.html
	www/config_errors.html
	www/config_restart.html
	www/threads_top.html
	www/foot.html
	www/assets/post.js
	www/assets/style.css
	www/assets/icons/datum_logo.svg
	www/assets/icons/favicon.ico
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(Threads REQUIRED)

set(POW_LIBS "")
include(CheckLibraryExists)
check_library_exists(m pow "" LIBM)
if(LIBM)
	list(APPEND POW_LIBS "m")
endif()

add_custom_target(generate_git_version
	BYPRODUCTS ${PROJECT_BINARY_DIR}/git_version.h
	COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/git_version.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
	DEPENDS cmake/script/GenerateBuildInfo.cmake
	COMMENT "Generating git_version.h"
	VERBATIM
)
add_dependencies(datum_gateway generate_git_version)

add_custom_command(
	OUTPUT web_resources.h
	COMMAND ${CMAKE_COMMAND} "-DINPUT_FILES=${WEB_RESOURCES}" -DOUTPUT_FILE=web_resources.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/EmbedResources.cmake
	DEPENDS ${WEB_RESOURCES} cmake/script/EmbedResources.cmake
	VERBATIM
)

target_include_directories(datum_gateway
	PRIVATE
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
	${CURL_INCLUDE_DIRS}
	${MICROHTTPD_INCLUDE_DIRS}
	${JANSSON_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS}
)
target_link_directories(datum_gateway
	PUBLIC
	${CURL_LIBRARY_DIRS}
	${MICROHTTPD_LIBRARY_DIRS}
	${JANSSON_LIBRARY_DIRS}
	${SODIUM_LIBRARY_DIRS}
)
target_link_libraries(datum_gateway
	PUBLIC
	${POW_LIBS}
	Threads::Threads
	${CURL_LIBRARIES} ${CURL_LDFLAGS} ${CURL_LDFLAGS_OTHER}
	${MICROHTTPD_LIBRARIES} ${MICROHTTPD_LDFLAGS} ${MICROHTTPD_LDFLAGS_OTHER}
	${JANSSON_LIBRARIES} ${JANSSON_LDFLAGS} ${JANSSON_LDFLAGS_OTHER}
	${SODIUM_LIBRARIES} ${SODIUM_LDFLAGS} ${SODIUM_LDFLAGS_OTHER}
)
target_compile_options(datum_gateway
	PUBLIC
	${CURL_CFLAGS} ${CURL_CFLAGS_OTHER}
	${MICROHTTPD_CFLAGS} ${MICROHTTPD_CFLAGS_OTHER}
	${JANSSON_CFLAGS} ${JANSSON_CFLAGS_OTHER}
	${SODIUM_CFLAGS} ${SODIUM_CFLAGS_OTHER}
)

install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES doc/DATUM_recommended_setup-network_diagram.svg DESTINATION ${CMAKE_INSTALL_DOCDIR}/doc)

set(PREGEN_DOC ${CMAKE_SOURCE_DIR}/doc/example_datum_gateway_config.json)
install(FILES ${PREGEN_DOC} DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(NOT CMAKE_CROSSCOMPILING)
	set(GENERATED_DOC ${CMAKE_BINARY_DIR}/CMakeFiles/generated_example_datum_gateway_config.json)
	
	add_custom_command(
		TARGET datum_gateway
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -DDATUM_GATEWAY=$<TARGET_FILE:datum_gateway> -DGENERATED_DOC=${GENERATED_DOC} -DPREGEN_DOC=${PREGEN_DOC} -P ${PROJECT_SOURCE_DIR}/cmake/script/VerifyExample.cmake
		COMMENT "Verifying pre-generated documentation is up-to-date"
		VERBATIM
	)
endif()
