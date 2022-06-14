add_library(tools SHARED "")
target_sources(tools PRIVATE tools.cpp)


project("daabridgecpp")

set (COMPILE_FLAGS "-O2")
add_definitions(-DTPM_POSIX -DTPM_TPM20)
#set(DEPENDENCY_LIST "")

## Need IBMTSS
#if(NOT (${IBMTSS_INCLUDE_PATH} AND ${IBMTSS_LIB_PATH}))
#    include(cmake/buildTSS.cmake)
#    include_directories(${IBMTSS_INCLUDE_PATH})
#    list(APPEND DEPENDENCY_LIST "IBMTSS")
#endif()

## Need OSSL
#if(NOT (${OPENSSL_INCLUDE_PATH} AND ${OPENSSL_LIB_PATH}))
#    include(cmake/buildOpenSSL.cmake)
#    include_directories(${OPENSSL_INCLUDE_PATH})
#    link_directories(${OPENSSL_LIB_PATH})
#    list(APPEND DEPENDENCY_LIST "OPENSSL")
#endif()

find_package(OpenSSL REQUIRED)
#target_link_libraries(untitled OpenSSL::SSL)

#link_directories(/home/benlar/Projects/OpenSSL/openssl_android/lib/x86_64)
#include_directories(/home/benlar/Projects/OpenSSL/openssl_android/inc/x86_64)

link_directories(/home/benlar/Projects/AndroidLibs/ibmtss/utils/.libs)
include_directories(/home/benlar/Projects/AndroidLibs/ibmtss/utils)

link_directories(/home/benlar/Projects/AndroidLibs/cJSON)
include_directories(/home/benlar/Projects/AndroidLibs/cJSON)


link_directories(/home/benlar/Projects/AndroidLibs/incubator-milagro-crypto-c/lib)
include_directories(/home/benlar/Projects/AndroidLibs/incubator-milagro-crypto-c/include)

#if(NOT (${AMCL_INCLUDE_PATH} AND ${AMCL_LIB_PATH}))
#    include(cmake/buildAMCL.cmake)
#    include_directories(${AMCL_INCLUDE_PATH})
#    list(APPEND DEPENDENCY_LIST "AMCL")
#endif()
#link_directories(${IBMTSS_LIB_PATH})
#link_directories(${AMCL_LIB_PATH})


## Need AMCL
#if(NOT (${AMCL_INCLUDE_PATH} AND ${AMCL_LIB_PATH}))
#    include(cmake/buildAMCL.cmake)
#    include_directories(${AMCL_INCLUDE_PATH})
#    link_directories(${AMCL_LIB_PATH})
#    list(APPEND DEPENDENCY_LIST "AMCL")
#endif()
#message(STATUS "Ossl: ${CMAKE_SOURCE_DIR}/ssl_lib")

add_library( # Sets the name of the library.
        daabridgecpp

        # Sets the library as a shared library.
        SHARED
        daa/defines.h daa/daa_client_base.h daa/daa_client_base.c daa/daa_issuer.h daa/BN_Crypto.h daa/BN_Crypto.c daa/daa_issuer.c daa/issPk.h daa/issPk.c daa/daa_pairings.h daa/daa_pairings.c
        daa_bridge.h daa_bridge.c persistence.h defines.h bridge_tpm.h bridge_tpm.c persistence.c hash.h hash.c policy.h cryptoutils.c cryptoutils.h  templates.h templates.c policy.c objecttemplates.h objecttemplates.c Test_issuer/issuer_interface.h Test_issuer/issuer_interface.c
        native-lib.cpp
        )

#message(STATUS "Dependencies that will be built: ${DEPENDENCY_LIST}")


target_link_libraries(daabridgecpp m crypto cjson ibmtss amcl_bls_FP256BN amcl_mpin_FP256BN amcl_curve_FP256BN amcl_pairing_FP256BN amcl_wcc_FP256BN)
#add_dependencies(daabridgecpp ${DEPENDENCY_LIST})