#include <net_cfg.h>
#include "../net_secure.h"
#include <KAL/kal.h>
#include <mbedtls/ssl.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

static int NetSecure_mbedtls_read(void *ctx, unsigned char *buf, size_t len);
static int NetSecure_mbedtls_write(void *ctx, const unsigned char *buf, size_t len);

static MEM_DYN_POOL NetSecure_SessionPool;
static CPU_SIZE_T  *SSL_StoreMemPtr;

                                                                /* Calculate RAM usage as recommended by SEGGER manual. */
#define  NET_SECURE_SSL_CONN_NBR_MAX          (NET_SECURE_CFG_MAX_NBR_SOCK_SERVER + NET_SECURE_CFG_MAX_NBR_SOCK_CLIENT)
//#define  NET_SECURE_SSL_MEM_SIZE              (((700u + 500u) + (2u * 16u * 1024u)) * NET_SECURE_SSL_CONN_NBR_MAX + 512u)
#define  NET_SECURE_SSL_MIN_MEM_SIZE          (34u * 1024u)
#define  NET_SECURE_SSL_MEM_SIZE              (100000)
typedef struct {
    CPU_CHAR                          *CommonNamePtr;
    NET_SOCK_SECURE_UNTRUSTED_REASON   UntrustedReason;
    NET_SOCK_SECURE_TRUST_FNCT         TrustCallbackFnctPtr;
    //NET_SECURE_EMSSL_DATA             *DataPtr;
    NET_SOCK_SECURE_TYPE               Type;
    mbedtls_ssl_context                 Context;
    mbedtls_x509_crt                    Cert;
    mbedtls_ssl_config                  Config;
    mbedtls_pk_context                  Key;
    mbedtls_ctr_drbg_context            Rng;
    mbedtls_entropy_context             Entropy;
} NetSecure_SSL_Context;

unsigned char memory_buf[100000];

#include <mbedtls/debug.h>

void NetSecure_Init(NET_ERR *p_err) {
  *p_err = NET_SECURE_ERR_NONE;
  LIB_ERR lib_err;

  SSL_StoreMemPtr = Mem_HeapAlloc(NET_SECURE_SSL_MEM_SIZE, sizeof(CPU_SIZE_T), NULL, &lib_err);

  mbedtls_memory_buffer_alloc_init( memory_buf, 100000 );

  
  mbedtls_debug_set_threshold(4);

    if (NET_SECURE_SSL_CONN_NBR_MAX > 0u) {
        Mem_DynPoolCreate("SSL Session pool",
                          &NetSecure_SessionPool,
                           DEF_NULL,
                           sizeof(NetSecure_SSL_Context),
                           sizeof(CPU_ALIGN),
                           0u,
                           NET_SECURE_SSL_CONN_NBR_MAX,
                          &lib_err);

        if (lib_err != LIB_MEM_ERR_NONE) {
            SSL_TRACE_DBG(("Mem_DynPoolCreate() returned an error"));
           *p_err = NET_SECURE_ERR_INIT_POOL;
            return;
        }
                                                                /* Allocate Heap space for emSSL.                       */
        SSL_StoreMemPtr = Mem_HeapAlloc( NET_SECURE_SSL_MEM_SIZE,
                                         sizeof(CPU_SIZE_T),
                                         DEF_NULL,
                                        &lib_err);
        if (lib_err != LIB_MEM_ERR_NONE) {
            SSL_TRACE_DBG(("Mem_HeapAlloc() returned an error"));
           *p_err = NET_SECURE_ERR_INIT_POOL;
            return;
        }
    } else {
        SSL_TRACE_DBG(("Invalid number of sessions in net_cfg.h"));
       *p_err = NET_SECURE_ERR_INIT_POOL;
        return;
    }
#if 0
                                                                /* Create mem pool of descriptors. One block per socket.*/
    if (NET_SECURE_CFG_MAX_NBR_SOCK_CLIENT > 0u) {
        Mem_DynPoolCreate("SSL Client Desc pool",
                          &NetSecure_ClientDescPool,
                           DEF_NULL,
                           sizeof(NET_SECURE_EMSSL_DATA),
                           sizeof(CPU_ALIGN),
                           0u,
                           NET_SECURE_CFG_MAX_NBR_SOCK_CLIENT,
                          &lib_err);
        if (lib_err != LIB_MEM_ERR_NONE) {
            SSL_TRACE_DBG(("Mem_DynPoolCreate() returned an error"));
           *p_err = NET_SECURE_ERR_INIT_POOL;
            return;
        }
    }

    if (NET_SECURE_CFG_MAX_NBR_SOCK_SERVER > 0u) {
        Mem_DynPoolCreate("SSL Server Desc pool",
                          &NetSecure_ServerDescPool,
                           DEF_NULL,
                           sizeof(NET_SECURE_EMSSL_DATA),
                           sizeof(CPU_ALIGN),
                           0u,
                           NET_SECURE_CFG_MAX_NBR_SOCK_SERVER,
                          &lib_err);
        if (lib_err != LIB_MEM_ERR_NONE) {
            SSL_TRACE_DBG(("Mem_DynPoolCreate() returned an error"));
           *p_err = NET_SECURE_ERR_INIT_POOL;
            return;
        }
    }

    SSL_Init();                                                 /* Initialize emSSL stack.                              */
#endif

}

void NetSecure_InitSession(NET_SOCK *p_sock, NET_ERR *p_err) {
  //mbedtls_ssl_init()
  NetSecure_SSL_Context *p_blk;
  LIB_ERR lib_err;

  p_blk = Mem_DynPoolBlkGet(&NetSecure_SessionPool, &lib_err);
  if (lib_err != LIB_MEM_ERR_NONE) {
      *p_err = NET_SECURE_ERR_NOT_AVAIL;
      return;
  }

#if (NET_DBG_CFG_MEM_CLR_EN == DEF_ENABLED)
  SSL_MEMSET(&p_blk->SessionCtx, 0, sizeof(p_blk->SessionCtx));
#endif

  //p_blk->DataPtr         = (void *)DEF_NULL;
  p_blk->Type            =  NET_SOCK_SECURE_TYPE_NONE;
  p_blk->UntrustedReason =  NET_SOCK_SECURE_UNKNOWN;
  p_sock->SecureSession  =  p_blk;

  mbedtls_ssl_init(&p_blk->Context);
  mbedtls_x509_crt_init(&p_blk->Cert);

  *p_err = NET_SECURE_ERR_NONE;
}

void NetSecure_SockClose(NET_SOCK *p_sock, NET_ERR *p_err) {
  //asm volatile("bkpt #0");
  printf("SSL-mbedtls: NetSecure_SockClose not yet implemented\n");
  //mbedtls_ssl_close_notify()
}

void NetSecure_SockCloseNotify(NET_SOCK *p_sock, NET_ERR *p_err) {
  //asm volatile("bkpt #0");
  printf("SSL-mbedtls: NetSecure_SockCloseNotify not yet implemented\n");
}

void NetSecure_SockConn(NET_SOCK *p_sock, NET_ERR *p_err) {
  //asm volatile("bkpt #0");
  printf("SSL-mbedtls: NetSecure_SockConn not yet implemented\n");
}

void NetSecure_SockAccept(NET_SOCK *p_sock_listen, NET_SOCK *p_sock_accept,
                          NET_ERR *p_err) {

    CPU_INT32S                 result;
    NetSecure_SSL_Context  *p_session_accept;
    NetSecure_SSL_Context  *p_session_listen;
    LIB_ERR                    lib_err;
    
    if (NetSecure_SessionPool.BlkAllocCnt == NetSecure_SessionPool.BlkQtyMax) {
        SSL_TRACE_DBG(("Error: NO SSL sessions available\n"));
       *p_err = NET_SECURE_ERR_NOT_AVAIL;
        return;
    }
/*
    if (NetSecure_ServerDescPool.BlkAllocCnt == NetSecure_ServerDescPool.BlkQtyMax) {
        SSL_TRACE_DBG(("Error: NO server sessions available\n"));
       *p_err = NET_SECURE_ERR_NOT_AVAIL;
        return;
    }
*/

    NetSecure_InitSession(p_sock_accept, p_err);                /* Initialize session context.                          */

    if (*p_err != NET_SECURE_ERR_NONE) {
        SSL_TRACE_DBG(("Error: NO session available\n"));
       *p_err = NET_SECURE_ERR_NOT_AVAIL;
        return;
    }

    p_session_accept = ((NetSecure_SSL_Context *)p_sock_accept->SecureSession);
    p_session_listen = ((NetSecure_SSL_Context *)p_sock_listen->SecureSession);

    if(mbedtls_ssl_setup(&p_session_accept->Context, &p_session_listen->Config) != 0) {
        *p_err = NET_SECURE_ERR_NULL_PTR;
        return;
    }

    mbedtls_ctr_drbg_seed( &p_session_accept->Rng, mbedtls_entropy_func, &p_session_accept->Entropy, 
        (const unsigned char *) "Hello world",11 );

/*
    mbedtls_ssl_config_defaults(&p_session_listen->Config, 
              MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, 
              MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_rng( &p_session_accept->Config, mbedtls_ctr_drbg_random, &p_session_accept->Rng );
*/
    mbedtls_ssl_set_bio(
        &p_session_accept->Context, 
        p_sock_accept, 
        NetSecure_mbedtls_write, 
        NetSecure_mbedtls_read, 
        NULL);

    int ret;

    //KAL_Dly(5000);
#if 0
    

    CPU_INT08U tmp_buffer[128];
    volatile NET_SOCK_RTN_CODE retCode = NetSock_RxDataHandlerStream(
        p_sock_accept->ID, p_sock_accept,
        tmp_buffer, sizeof(tmp_buffer), 
        0, 0, 0,
        p_err);
    NetSock_TxDataHandlerStream(p_sock_accept->ID, p_sock_accept, "HEllo world", 11, 0, p_err);
#endif
    #if 1
    while( ( ret = mbedtls_ssl_handshake(&p_session_accept->Context) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            //mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
            //goto reset;
            break;
        }
    }
    #endif

    *p_err = NET_SOCK_ERR_NONE;
    //asm volatile("bkpt #0");
}

static void ssl_debug_fn(void * ctx, int level, const char * filename, int line, const char * msg) {
    printf("%s", msg);
}

CPU_BOOLEAN
NetSecure_SockCertKeyCfg(NET_SOCK *p_sock, NET_SOCK_SECURE_TYPE sock_type,
                         const CPU_INT08U *p_buf_cert, CPU_SIZE_T buf_cert_size,
                         const CPU_INT08U *p_buf_key, CPU_SIZE_T buf_key_size,
                         NET_SOCK_SECURE_CERT_KEY_FMT fmt,
                         CPU_BOOLEAN cert_chain, NET_ERR *p_err) {
  
    NetSecure_SSL_Context  *p_session_desc;
    LIB_ERR                    lib_err;
    CPU_SR_ALLOC();


   (void)cert_chain;

#if 0
#if (NET_ERR_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if ((buf_cert_size >  NET_SECURE_CFG_MAX_CERT_LEN) ||
        (buf_cert_size == 0u)) {
       *p_err = NET_SECURE_ERR_INSTALL;
        return (DEF_FAIL);
    }

    if ((buf_key_size >  NET_SECURE_CFG_MAX_KEY_LEN) ||
        (buf_key_size == 0u)) {
       *p_err = NET_SECURE_ERR_INSTALL;
        return (DEF_FAIL);
    }

    if (fmt != NET_SOCK_SECURE_CERT_KEY_FMT_DER) {              /* See Note 2.                                          */
       *p_err = NET_SECURE_ERR_INSTALL;
        return (DEF_FAIL);
    }
#endif
#endif
  

    p_session_desc = (NetSecure_SSL_Context *)p_sock->SecureSession;
   *p_err          =  NET_SECURE_ERR_NONE;

    if (p_session_desc == (void *)0) {
       *p_err = NET_SOCK_ERR_NULL_PTR;
        return (DEF_FAIL);
    }

    CPU_CRITICAL_ENTER();
    p_session_desc->Type = sock_type;

    if (mbedtls_x509_crt_parse(&p_session_desc->Cert, (const unsigned char *) p_buf_cert, buf_cert_size) != 0) {
        //print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        *p_err = NET_SECURE_ERR_INSTALL;
        return;
    }

    if(mbedtls_pk_parse_key( &p_session_desc->Key, (const unsigned char *) p_buf_key, buf_key_size, NULL, 0 ) != 0) {
        *p_err = NET_SECURE_ERR_INSTALL;
        return;
    }

    if(mbedtls_ssl_conf_own_cert( &p_session_desc->Config, &p_session_desc->Cert, &p_session_desc->Key) != 0) {
        *p_err = NET_SECURE_ERR_INSTALL;
        return;
    }

    mbedtls_ssl_conf_dbg(&p_session_desc->Config, ssl_debug_fn, 0);

    mbedtls_ctr_drbg_seed( &p_session_desc->Rng, mbedtls_entropy_func, &p_session_desc->Entropy, 
        (const unsigned char *) "Hello world",11 );

    switch (sock_type) {
        case NET_SOCK_SECURE_TYPE_SERVER:
            if(mbedtls_ssl_config_defaults(&p_session_desc->Config, 
              MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, 
              MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
                *p_err = NET_SECURE_ERR_INSTALL;
                return;
              }

              mbedtls_ssl_conf_rng( &p_session_desc->Config, mbedtls_ctr_drbg_random, &p_session_desc->Rng );
             //if (p_session_desc->DataPtr) {
             //   *p_err = NET_SECURE_ERR_INSTALL;
             //    break;
             //}
             //p_session_desc->DataPtr = Mem_DynPoolBlkGet(&NetSecure_ServerDescPool, &lib_err);
             //if (lib_err != LIB_MEM_ERR_NONE) {
             //   *p_err = NET_SECURE_ERR_INSTALL;
             //    break;
             //}
             //p_session_desc->DataPtr->ServerCertPtr    = ((SSL_ROOT_CERTIFICATE *)p_buf_cert)->pData->pCertDER;
             //p_session_desc->DataPtr->ServerPrivKeyPtr = p_buf_key;
             //p_session_desc->DataPtr->ServerCertLen    = buf_cert_size;
             //p_session_desc->DataPtr->ServerPrivKeyLen = buf_key_size;
             break;

#if 0
        case NET_SOCK_SECURE_TYPE_CLIENT:
             if (p_session_desc->DataPtr == DEF_NULL) {
                 p_session_desc->DataPtr = Mem_DynPoolBlkGet(&NetSecure_ClientDescPool, &lib_err);
                 if (lib_err != LIB_MEM_ERR_NONE) {
                    *p_err = NET_SECURE_ERR_INSTALL;
                     break;
                 }
             }
#if (EMSSL_MUTUAL_AUTH_EN == DEF_ENABLED)
             p_session_desc->DataPtr->ClientCertPtr    = ((SSL_ROOT_CERTIFICATE *)p_buf_cert)->pData->pCertDER;
             p_session_desc->DataPtr->ClientPrivKeyPtr = p_buf_key;
             p_session_desc->DataPtr->ClientCertLen    = buf_cert_size;
             p_session_desc->DataPtr->ClientPrivKeyLen = buf_key_size;
#else
            *p_err = NET_SECURE_ERR_INSTALL;
#endif
             break;

#endif
        default:
            *p_err = NET_SECURE_ERR_INSTALL;
             break;
    }

    mbedtls_ssl_conf_ca_chain( &p_session_desc->Config, &p_session_desc->Cert, NULL );
    mbedtls_ssl_conf_authmode(&p_session_desc->Config, MBEDTLS_SSL_VERIFY_OPTIONAL);

#if 0 // ist dies notwendig für den server socket ???
    if(mbedtls_ssl_setup( &p_session_desc->Context, &p_session_desc->Config ) != 0) {
      *p_err = NET_SECURE_ERR_INSTALL;
      return;
    }
#endif

    CPU_CRITICAL_EXIT();
    if (*p_err != NET_SECURE_ERR_NONE) {
        return (DEF_FAIL);
    }

    return (DEF_OK);
}

NET_SOCK_RTN_CODE NetSecure_SockRxDataHandler(NET_SOCK *p_sock,
                                              void *p_data_buf,
                                              CPU_INT16U data_buf_len,
                                              NET_ERR *p_err) {

    NET_SOCK_RTN_CODE ret_err;

    NetSecure_SSL_Context* p_session = p_sock->SecureSession;

    ret_err = NET_SOCK_BSD_ERR_RX;

    if(p_session == 0) {
        p_err = NET_SECURE_ERR_NULL_PTR;
        return ret_err;
    }

    mbedtls_ssl_read(&p_session->Context, p_data_buf, data_buf_len);
    //asm volatile("bkpt #0");
}


NET_SOCK_RTN_CODE NetSecure_SockTxDataHandler(NET_SOCK *p_sock,
                                              void *p_data_buf,
                                              CPU_INT16U data_buf_len,
                                              NET_ERR *p_err) {

    CPU_INT32S          result;
    NetSecure_SSL_Context* p_session = p_sock;
    NET_SOCK_RTN_CODE   ret_err;
    NET_SOCK_ID         sock_id;
    NET_ERR             net_err;


    ret_err   =  NET_SOCK_BSD_ERR_TX;
   *p_err     =  NET_SOCK_ERR_NONE;
    sock_id   =  p_sock->ID;
    p_session = (NetSecure_SSL_Context *)p_sock->SecureSession;

    if (p_sock->SecureSession == (NetSecure_SSL_Context *)0) {
       *p_err = NET_SECURE_ERR_NULL_PTR;
        return (ret_err);
    }
             
                                                       /* Only use SSL_SESSION_Send() if handshake succeeded.  */
    //if (p_session->State == SSL_CONNECTED) 
    {
        //result = SSL_SESSION_Send(p_session,
        //                          p_data_buf,
        //                          data_buf_len);
        result = mbedtls_ssl_write(&p_session->Context, p_data_buf, data_buf_len);
    } 
    //else 
    //{
    //    result = NetSock_TxDataHandlerStream( sock_id,
    //                                          p_sock,
    //                                          p_data_buf,
    //                                          data_buf_len,
    //                                          NET_SOCK_FLAG_NONE,
    //                                         &net_err);
    //}

    if (result < 0) {
       *p_err = NET_ERR_TX;
    } else {
        ret_err = result;
    }

    return (ret_err);


                                              }


int NetSecure_mbedtls_read(void *ctx, unsigned char *buf, size_t len) {
    NET_SOCK* p_sock = ctx;
    NET_ERR net_err;
    NET_SOCK_RTN_CODE ret;
    CPU_BOOLEAN block;

    block = DEF_BIT_IS_CLR(p_sock->Flags, NET_SOCK_FLAG_SOCK_NO_BLOCK);
    DEF_BIT_CLR(p_sock->Flags, NET_SOCK_FLAG_SOCK_NO_BLOCK);


    ret = NetSock_RxDataHandlerStream(p_sock->ID, p_sock, buf, len, 0, 0, 0, &net_err);

    if (!block) {
        DEF_BIT_SET(p_sock->Flags, NET_SOCK_FLAG_SOCK_NO_BLOCK);
    }

    if(ret < 0) {
    //    asm volatile("bkpt #0");
    }
    return ret;
}

int NetSecure_mbedtls_write(void *ctx, const unsigned char *buf, size_t len) {
    NET_SOCK* p_sock = ctx;
    NET_ERR net_err;
    NET_SOCK_RTN_CODE ret = NET_SOCK_BSD_ERR_TX;

    if ((p_sock->State != NET_SOCK_STATE_CONN     )  &&         /* Data cannot be sent if socket is closed or closing.  */
        (p_sock->State != NET_SOCK_STATE_CONN_DONE)) {
        printf("SSL: socket closed or closing\n");
        return (ret);
    }
    
    ret = NetSock_TxDataHandlerStream(p_sock->ID, p_sock, buf, len, 0, &net_err);

    

    if(ret < 0) {
        //asm volatile("bkpt #0");
        //printf("SSL: rx error: %d\n", ret);
    }
    return ret;
}

#if (NET_SOCK_CFG_SEL_EN == DEF_ENABLED)
CPU_BOOLEAN         NetSecure_SockRxIsDataPending   (       NET_SOCK                      *p_sock,
                                                            NET_ERR                       *p_err) {
                                                                return DEF_FALSE;
                                                            }
#endif