# Uart 샘플에 Aes(암호화) 적용 방법

- mcu : nrf52832

# 비고
- nrf52832에서는 하드웨어 암호화(cc310)를 지원하지 않아 mbed를 이용한다.

# 방법
## 1. 프로젝트 파일 수정

1) c_user_include_directories
맨 뒤에 경로 삽입, (불필요한 요소 확인 후 제거)

```
../../../../../../components/libraries/crypto;../../../../../../components/libraries/csense;../../../../../../components/libraries/csense_drv;../../../../../../components/libraries/delay;../../../../../../components/libraries/ecc;../../../../../../components/libraries/experimental_section_vars;../../../../../../components/libraries/experimental_task_manager;../../../../../../components/libraries/fds;../../../../../../components/libraries/fifo;../../../../../../components/libraries/fstorage;../../../../../../components/libraries/gfx;../../../../../../components/libraries/gpiote;../../../../../../components/libraries/hardfault;../../../../../../components/libraries/hci;../../../../../../components/libraries/led_softblink;../../../../../../components/libraries/log;../../../../../../components/libraries/log/src;../../../../../../components/libraries/low_power_pwm;../../../../../../components/libraries/mem_manager;../../../../../../components/libraries/memobj;../../../../../../components/libraries/mpu;../../../../../../components/libraries/mutex;../../../../../../components/libraries/pwm;../../../../../../components/libraries/pwr_mgmt;../../../../../../components/libraries/queue;../../../../../../components/libraries/ringbuf;../../../../../../components/libraries/scheduler;../../../../../../components/libraries/sdcard;../../../../../../components/libraries/slip;../../../../../../components/libraries/sortlist;../../../../../../components/libraries/spi_mngr;../../../../../../components/libraries/stack_guard;../../../../../../components/libraries/strerror;../../../../../../components/libraries/svc;../../../../../../components/libraries/timer;../../../../../../components/libraries/twi_mngr;../../../../../../components/libraries/twi_sensor;../../../../../../components/libraries/uart;../../../../../../components/libraries/usbd;../../../../../../components/libraries/usbd/class/audio;../../../../../../components/libraries/usbd/class/cdc;../../../../../../components/libraries/usbd/class/cdc/acm;../../../../../../components/libraries/usbd/class/hid;../../../../../../components/libraries/usbd/class/hid/generic;../../../../../../components/libraries/usbd/class/hid/kbd;../../../../../../components/libraries/usbd/class/hid/mouse;../../../../../../components/libraries/usbd/class/msc;../../../../../../components/libraries/util;../../../../../../components/nfc/ndef/conn_hand_parser;../../../../../../components/nfc/ndef/conn_hand_parser/ac_rec_parser;../../../../../../components/nfc/ndef/conn_hand_parser/ble_oob_advdata_parser;../../../../../../components/nfc/ndef/conn_hand_parser/le_oob_rec_parser;../../../../../../components/nfc/ndef/connection_handover/ac_rec;../../../../../../components/nfc/ndef/connection_handover/ble_oob_advdata;../../../../../../components/nfc/ndef/connection_handover/ble_pair_lib;../../../../../../components/nfc/ndef/connection_handover/ble_pair_msg;../../../../../../components/nfc/ndef/connection_handover/common;../../../../../../components/nfc/ndef/connection_handover/ep_oob_rec;../../../../../../components/nfc/ndef/connection_handover/hs_rec;../../../../../../components/nfc/ndef/connection_handover/le_oob_rec;../../../../../../components/nfc/ndef/generic/message;../../../../../../components/nfc/ndef/generic/record;../../../../../../components/nfc/ndef/launchapp;../../../../../../components/nfc/ndef/parser/message;../../../../../../components/nfc/ndef/parser/record;../../../../../../components/nfc/ndef/text;../../../../../../components/nfc/ndef/uri;../../../../../../components/nfc/platform;../../../../../../components/nfc/t2t_lib;../../../../../../components/nfc/t2t_parser;../../../../../../components/nfc/t4t_lib;../../../../../../components/nfc/t4t_parser/apdu;../../../../../../components/nfc/t4t_parser/cc_file;../../../../../../components/nfc/t4t_parser/hl_detection_procedure;../../../../../../components/nfc/t4t_parser/tlv;../../../../../../components/softdevice/common;../../../../../../components/softdevice/s132/headers;../../../../../../components/softdevice/s132/headers/nrf52;../../../../../../components/toolchain/cmsis/include;../../../../../../external/fprintf;../../../../../../external/segger_rtt;../../../../../../external/utf_converter;../../../../../../integration/nrfx;../../../../../../integration/nrfx/legacy;../../../../../../modules/nrfx;../../../../../../modules/nrfx/drivers/include;../../../../../../modules/nrfx/hal;../../../../../../modules/nrfx/mdk;../config;../../../../../../components/libraries/crypto;../../../../../../components/libraries/crypto/backend/cc310;../../../../../../components/libraries/crypto/backend/cc310_bl;../../../../../../components/libraries/crypto/backend/cifra;../../../../../../components/libraries/crypto/backend/mbedtls;../../../../../../components/libraries/crypto/backend/micro_ecc;../../../../../../components/libraries/crypto/backend/nrf_hw;../../../../../../components/libraries/crypto/backend/nrf_sw;../../../../../../components/libraries/crypto/backend/oberon;../../../../../../components/libraries/crypto/backend/optiga;../../../../../../components/libraries/delay;../../../../../../components/libraries/experimental_section_vars;../../../../../../components/libraries/hardfault;../../../../../../components/libraries/hardfault/nrf52;../../../../../../components/libraries/log;../../../../../../components/libraries/log/src;../../../../../../components/libraries/mem_manager;../../../../../../components/libraries/memobj;../../../../../../components/libraries/mutex;../../../../../../components/libraries/queue;../../../../../../components/libraries/ringbuf;../../../../../../components/libraries/scheduler;../../../../../../components/libraries/sortlist;../../../../../../components/libraries/stack_info;../../../../../../components/libraries/strerror;../../../../../../components/libraries/timer;../../../../../../components/libraries/util;../../../../../../components/toolchain/cmsis/include;../../..;../../../../../../external/cifra_AES128-EAX;../../../../../../external/fprintf;../../../../../../external/mbedtls/include;../../../../../../external/micro-ecc/micro-ecc;../../../../../../external/nrf_cc310/include;../../../../../../external/nrf_oberon;../../../../../../external/nrf_oberon/include;../../../../../../external/nrf_tls/mbedtls/nrf_crypto/config;
```

2) c_preprocessor_definitions 수정
아래 명령어 추가
```
MBEDTLS_CONFIG_FILE=&quot;nrf_crypto_mbedtls_config.h&quot;;NRF_CRYPTO_MAX_INSTANCE_COUNT=1;
```

3) 폴더 추가
```
    <folder Name="nRF_Crypto">
      <file file_name="../../../../../../components/libraries/crypto/nrf_crypto_aead.c" />
      <file file_name="../../../../../../components/libraries/crypto/nrf_crypto_aes_shared.c" />
      <file file_name="../../../../../../components/libraries/crypto/nrf_crypto_error.c" />
      <file file_name="../../../../../../components/libraries/crypto/nrf_crypto_init.c" />
      <file file_name="../../../../../../components/libraries/crypto/nrf_crypto_shared.c" />
    </folder>
    <folder Name="nRF_Crypto backend mbed TLS">
      <file file_name="../../../../../../components/libraries/crypto/backend/mbedtls/mbedtls_backend_aes_aead.c" />
      <file file_name="../../../../../../components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecc.c" />
      <file file_name="../../../../../../components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdh.c" />
      <file file_name="../../../../../../components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdsa.c" />
      <file file_name="../../../../../../components/libraries/crypto/backend/mbedtls/mbedtls_backend_init.c" />
    </folder>
    <folder Name="nRF_TLS">
      <file file_name="../../../../../../external/mbedtls/library/aes.c" />
      <file file_name="../../../../../../external/mbedtls/library/aesni.c" />
      <file file_name="../../../../../../external/mbedtls/library/arc4.c" />
      <file file_name="../../../../../../external/mbedtls/library/aria.c" />
      <file file_name="../../../../../../external/mbedtls/library/asn1parse.c" />
      <file file_name="../../../../../../external/mbedtls/library/asn1write.c" />
      <file file_name="../../../../../../external/mbedtls/library/base64.c" />
      <file file_name="../../../../../../external/mbedtls/library/bignum.c" />
      <file file_name="../../../../../../external/mbedtls/library/blowfish.c" />
      <file file_name="../../../../../../external/mbedtls/library/camellia.c" />
      <file file_name="../../../../../../external/mbedtls/library/ccm.c" />
      <file file_name="../../../../../../external/mbedtls/library/certs.c" />
      <file file_name="../../../../../../external/mbedtls/library/chacha20.c" />
      <file file_name="../../../../../../external/mbedtls/library/chachapoly.c" />
      <file file_name="../../../../../../external/mbedtls/library/cipher.c" />
      <file file_name="../../../../../../external/mbedtls/library/cipher_wrap.c" />
      <file file_name="../../../../../../external/mbedtls/library/cmac.c" />
      <file file_name="../../../../../../external/mbedtls/library/ctr_drbg.c" />
      <file file_name="../../../../../../external/mbedtls/library/debug.c" />
      <file file_name="../../../../../../external/mbedtls/library/des.c" />
      <file file_name="../../../../../../external/mbedtls/library/dhm.c" />
      <file file_name="../../../../../../external/mbedtls/library/ecdh.c" />
      <file file_name="../../../../../../external/mbedtls/library/ecdsa.c" />
      <file file_name="../../../../../../external/mbedtls/library/ecjpake.c" />
      <file file_name="../../../../../../external/mbedtls/library/ecp.c" />
      <file file_name="../../../../../../external/mbedtls/library/ecp_curves.c" />
      <file file_name="../../../../../../external/mbedtls/library/entropy.c" />
      <file file_name="../../../../../../external/mbedtls/library/entropy_poll.c" />
      <file file_name="../../../../../../external/mbedtls/library/error.c" />
      <file file_name="../../../../../../external/mbedtls/library/gcm.c" />
      <file file_name="../../../../../../external/mbedtls/library/havege.c" />
      <file file_name="../../../../../../external/mbedtls/library/hmac_drbg.c" />
      <file file_name="../../../../../../external/mbedtls/library/md.c" />
      <file file_name="../../../../../../external/mbedtls/library/md2.c" />
      <file file_name="../../../../../../external/mbedtls/library/md4.c" />
      <file file_name="../../../../../../external/mbedtls/library/md5.c" />
      <file file_name="../../../../../../external/mbedtls/library/md_wrap.c" />
      <file file_name="../../../../../../external/mbedtls/library/memory_buffer_alloc.c" />
      <file file_name="../../../../../../external/mbedtls/library/net_sockets.c" />
      <file file_name="../../../../../../external/mbedtls/library/nist_kw.c" />
      <file file_name="../../../../../../external/mbedtls/library/oid.c" />
      <file file_name="../../../../../../external/mbedtls/library/padlock.c" />
      <file file_name="../../../../../../external/mbedtls/library/pem.c" />
      <file file_name="../../../../../../external/mbedtls/library/pk.c" />
      <file file_name="../../../../../../external/mbedtls/library/pk_wrap.c" />
      <file file_name="../../../../../../external/mbedtls/library/pkcs11.c" />
      <file file_name="../../../../../../external/mbedtls/library/pkcs12.c" />
      <file file_name="../../../../../../external/mbedtls/library/pkcs5.c" />
      <file file_name="../../../../../../external/mbedtls/library/pkparse.c" />
      <file file_name="../../../../../../external/mbedtls/library/pkwrite.c" />
      <file file_name="../../../../../../external/mbedtls/library/platform.c" />
      <file file_name="../../../../../../external/mbedtls/library/platform_util.c" />
      <file file_name="../../../../../../external/mbedtls/library/poly1305.c" />
      <file file_name="../../../../../../external/mbedtls/library/ripemd160.c" />
      <file file_name="../../../../../../external/mbedtls/library/rsa.c" />
      <file file_name="../../../../../../external/mbedtls/library/rsa_internal.c" />
      <file file_name="../../../../../../external/mbedtls/library/sha1.c" />
      <file file_name="../../../../../../external/mbedtls/library/sha256.c" />
      <file file_name="../../../../../../external/mbedtls/library/sha512.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_cache.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_ciphersuites.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_cli.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_cookie.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_srv.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_ticket.c" />
      <file file_name="../../../../../../external/mbedtls/library/ssl_tls.c" />
      <file file_name="../../../../../../external/mbedtls/library/threading.c" />
      <file file_name="../../../../../../external/mbedtls/library/version.c" />
      <file file_name="../../../../../../external/mbedtls/library/version_features.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509_create.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509_crl.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509_crt.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509_csr.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509write_crt.c" />
      <file file_name="../../../../../../external/mbedtls/library/x509write_csr.c" />
      <file file_name="../../../../../../external/mbedtls/library/xtea.c" />
    </folder>
```


## 2.sdk_config 수정
```
    // <h> nRF_Crypto

//==========================================================
// <e> NRF_CRYPTO_ENABLED - nrf_crypto - Cryptography library.
//==========================================================
#ifndef NRF_CRYPTO_ENABLED
#define NRF_CRYPTO_ENABLED 1
#endif
// <o> NRF_CRYPTO_ALLOCATOR  - Memory allocator
 

// <i> Choose memory allocator used by nrf_crypto. Default is alloca if possible or nrf_malloc otherwise. If 'User macros' are selected, the user has to create 'nrf_crypto_allocator.h' file that contains NRF_CRYPTO_ALLOC, NRF_CRYPTO_FREE, and NRF_CRYPTO_ALLOC_ON_STACK.
// <0=> Default
// <1=> User macros
// <2=> On stack (alloca)
// <3=> C dynamic memory (malloc)
// <4=> SDK Memory Manager (nrf_malloc)

#ifndef NRF_CRYPTO_ALLOCATOR
#define NRF_CRYPTO_ALLOCATOR 3
#endif


// <e> NRF_CRYPTO_BACKEND_MBEDTLS_ENABLED - Enable the mbed TLS backend.
//==========================================================
#ifndef NRF_CRYPTO_BACKEND_MBEDTLS_ENABLED
#define NRF_CRYPTO_BACKEND_MBEDTLS_ENABLED 1
#endif
// <q> NRF_CRYPTO_BACKEND_MBEDTLS_AES_CCM_ENABLED  - Enable the AES CCM mode using mbed TLS.
 

#ifndef NRF_CRYPTO_BACKEND_MBEDTLS_AES_CCM_ENABLED
#define NRF_CRYPTO_BACKEND_MBEDTLS_AES_CCM_ENABLED 1
#endif

// <q> NRF_CRYPTO_BACKEND_MBEDTLS_AES_GCM_ENABLED  - Enable the AES GCM mode using mbed TLS.
 

#ifndef NRF_CRYPTO_BACKEND_MBEDTLS_AES_GCM_ENABLED
#define NRF_CRYPTO_BACKEND_MBEDTLS_AES_GCM_ENABLED 1
#endif

// </e>

// </e>

// </e>
```

## 3.mac.c
암호화 예제 참조

``` 선언
#include <ctype.h>
#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
```

``` 함수

// for crypto
#define AES_MAC_SIZE                            (16)

#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE    (100)

#define AES_ERROR_CHECK(error)  \
    do {            \
        if (error)  \
        {           \
            NRF_LOG_RAW_INFO("\r\nError = 0x%x\r\n%s\r\n",           \
                             (error),                                \
                             nrf_crypto_error_string_get(error));    \
            return; \
        }           \
    } while (0);



/* Maximum allowed key = 256 bit */
static uint8_t m_key[32] = {'N', 'O', 'R', 'D', 'I', 'C', ' ',
                            'S', 'E', 'M', 'I', 'C', 'O', 'N', 'D', 'U', 'C', 'T', 'O', 'R',
                            'A', 'E', 'S', '&', 'M', 'A', 'C', ' ', 'T', 'E', 'S', 'T'};

/* Below text is used as plain text for encryption, decryption and MAC calculation. */
static char m_plain_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE] =
{
    "Example string used to demonstrate basic usage of AES CCM mode."
};

static char m_encrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
static char m_decrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];

static void text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("----%s (len: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();
    for(size_t i = 0; i < len; i++)
    {
        NRF_LOG_RAW_INFO("%c", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}

static void hex_text_print(char const* p_label, char const * p_text, size_t len)
{
    NRF_LOG_RAW_INFO("---- %s (len: %u) ----\r\n", p_label, len);
    NRF_LOG_FLUSH();

    // Handle partial line (left)
    for (size_t i = 0; i < len; i++)
    {
        if (((i & 0xF) == 0) && (i > 0))
        {
            NRF_LOG_RAW_INFO("\r\n");
            NRF_LOG_FLUSH();
        }

        NRF_LOG_RAW_INFO("%02x ", p_text[i]);
        NRF_LOG_FLUSH();
    }
    NRF_LOG_RAW_INFO("\r\n");
    NRF_LOG_RAW_INFO("---- %s end ----\r\n\r\n", p_label);
    NRF_LOG_FLUSH();
}



static void plain_text_print(void)
{
    text_print("Plain text", m_plain_text, strlen(m_plain_text));
    hex_text_print("Plain text (hex)", m_plain_text, strlen(m_plain_text));
}

static void encrypted_text_print(char const * p_text, size_t encrypted_len)
{
    hex_text_print("Encrypted text (hex)", p_text, encrypted_len);
}

static void decrypted_text_print(char const * p_text, size_t decrypted_len)
{
    text_print("Decrypted text", p_text, decrypted_len);
    hex_text_print("Decrypted text (hex)", p_text, decrypted_len);
}

static void mac_print(uint8_t const * p_buff, uint8_t mac_size)
{
    hex_text_print("MAC (hex)", (char const*)p_buff, mac_size);
}

static void crypt_test(bool ccm)
{
    uint32_t    len;
    ret_code_t  ret_val;

    static uint8_t     mac[AES_MAC_SIZE];
    static uint8_t     nonce[13];
    static uint8_t     adata[] = {0xAA, 0xBB, 0xCC, 0xDD};

    static nrf_crypto_aead_context_t ccm_ctx;

    memset(mac,   0, sizeof(mac));
    memset(nonce, 0, sizeof(nonce));

    plain_text_print();

    len = strlen((char const *)m_plain_text);

    //seelct ccm OR gcm
    nrf_crypto_aead_info_t* p_aead_info;
    if (ccm)
      p_aead_info = &g_nrf_crypto_aes_ccm_128_info;
    else
      p_aead_info = &g_nrf_crypto_aes_gcm_128_info;

    /* Init encrypt and decrypt context */
    ret_val = nrf_crypto_aead_init(&ccm_ctx,
                                   p_aead_info,
                                   m_key);
    AES_ERROR_CHECK(ret_val);

    /* encrypt and tag text */
    ret_val = nrf_crypto_aead_crypt(&ccm_ctx,
                                    NRF_CRYPTO_ENCRYPT,
                                    nonce,
                                    sizeof(nonce),
                                    adata,
                                    sizeof(adata),
                                    (uint8_t *)m_plain_text,
                                    len,
                                    (uint8_t *)m_encrypted_text,
                                    mac,
                                    sizeof(mac));
    AES_ERROR_CHECK(ret_val);

    encrypted_text_print(m_encrypted_text, len);
    mac_print(mac, sizeof(mac));

    /* decrypt text */
    ret_val = nrf_crypto_aead_crypt(&ccm_ctx,
                                    NRF_CRYPTO_DECRYPT,
                                    nonce,
                                    sizeof(nonce),
                                    adata,
                                    sizeof(adata),
                                    (uint8_t *)m_encrypted_text,
                                    len,
                                    (uint8_t *)m_decrypted_text,
                                    mac,
                                    sizeof(mac));
    AES_ERROR_CHECK(ret_val);

    ret_val = nrf_crypto_aead_uninit(&ccm_ctx);
    AES_ERROR_CHECK(ret_val);

    decrypted_text_print(m_decrypted_text, len);

    if (memcmp(m_plain_text, m_decrypted_text, strlen(m_plain_text)) == 0)
    {
        if(ccm)
        {
          NRF_LOG_RAW_INFO("AES CCM example executed successfully.\r\n");
        }
        else
        {
          NRF_LOG_RAW_INFO("AES GCM example executed successfully.\r\n");
        }
    }
    else
    {
        NRF_LOG_RAW_INFO("AES CCM example failed!!!.\r\n");
    }
}

```

``` init
ret = nrf_crypto_init();
APP_ERROR_CHECK(ret);

```