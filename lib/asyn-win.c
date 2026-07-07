/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

 // Win32 async DNS requires UNICODE
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "curl_setup.h"
#include "socketpair.h"

/***********************************************************************
 * Only for Win32 name resolver builds
 **********************************************************************/
#ifdef CURLRES_WIN32

#include "urldata.h"
#include "cfilters.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"
#include "multiif.h"
#include "curl_threads.h"
#include "select.h"
#include "strdup.h"

 /* The last 3 #include files should be in this order */
#include "connect.h"
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
#include "system_win32.h"
#include "curlx/multibyte.h"
#include "curlx/version_win32.h"

#if _WIN32_WINNT < 0x0501
#error Win32 resolver requires targetting at least Windows XP
#endif

#ifndef USE_WINSOCK
#error Win32 resolver requires WinSock
#endif

typedef enum {
  ASYNC_NOTSTARTED = 0,
  ASYNC_PENDING,
  ASYNC_FINISHED
} ASYNCstatus;

/* This is used to dynamically load DLLs */
static bool async_win32_supports_async;

/* This is used to dynamically load DLLs */
static bool async_win32_supports_custom_servers;

#ifdef USE_HTTPSRR
/* This is used to dynamically load DLLs */
static bool async_win32_supports_httpsrr;
#endif

/*
 * Curl_async_global_init()
 * Called from curl_global_init() to initialize global resolver environment.
 */
int Curl_async_global_init(void)
{
  async_win32_supports_async = Curl_GetAddrInfoExCancel && Curl_WaitOnAddress && Curl_WakeByAddressAll;
  async_win32_supports_custom_servers = async_win32_supports_async && curlx_verify_windows_version(10, 0, 22000, PLATFORM_DONT_CARE, VERSION_GREATER_THAN_EQUAL);

#ifdef USE_HTTPSRR
  async_win32_supports_httpsrr = async_win32_supports_custom_servers && Curl_DnsQueryEx && Curl_DnsCancelQuery && curlx_verify_windows_version(10, 0, 22621, PLATFORM_DONT_CARE, VERSION_GREATER_THAN_EQUAL);
#endif

  return CURLE_OK;
}

/*
 * Curl_async_global_cleanup()
 * Called from curl_global_cleanup() to destroy global resolver environment.
 */
void Curl_async_global_cleanup(void)
{
  /* No cleanup needed */
}

CURLcode Curl_async_get_impl(struct Curl_easy* data, void** impl)
{
  (void)data;
  *impl = NULL;
  return CURLE_OK;
}

void async_win32_wait(volatile unsigned char* handle)
{
  WAITONADDRESS_FN waitonaddress = Curl_WaitOnAddress;

  if (!waitonaddress) {
    DEBUGASSERT(!async_win32_supports_async);
    DEBUGASSERT(*handle != ASYNC_PENDING);
    return;
  }

  while (*handle == ASYNC_PENDING) {
    unsigned char pending_value = ASYNC_PENDING;
    waitonaddress(handle, &pending_value, sizeof(unsigned char), INFINITE);
  }
}

void async_win32_release(volatile unsigned char* handle, unsigned char status)
{
  WAKEBYADDRESSALL_FN wakebyaddressall = Curl_WakeByAddressAll;

#ifdef DEBUGBUILD
  Curl_resolve_test_delay();
#endif

  *handle = status;

  if (!wakebyaddressall) {
    DEBUGASSERT(!async_win32_supports_async);
    return;
  }

  wakebyaddressall((PVOID)handle);
}

/*
 * getaddrinfo_thread() resolves a name and then exits.
 *
 * For builds without ARES, but with USE_IPV6, create a resolver thread
 * and wait on it.
 */
static CURL_THREAD_RETURN_T CURL_STDCALL getaddrinfo_thread(void* arg)
{
  struct async_win32_request_ctx* addr_ctx = arg;
  int rc;

  {
    char service[12];

    msnprintf(service, sizeof(service), "%d", addr_ctx->port);

    rc = Curl_getaddrinfo_ex(addr_ctx->hostname, service,
      &addr_ctx->hints, &addr_ctx->res);
  }

  if (rc) {
    addr_ctx->sock_error = SOCKERRNO ? SOCKERRNO : rc;
    if (!addr_ctx->sock_error)
      addr_ctx->sock_error = RESOLVER_ENOMEM;
  }
  else {
    Curl_addrinfo_set_port(addr_ctx->res, addr_ctx->port);
  }

  return 0;
}

/* Initialize request context */
static CURLcode
async_win32_request_init(struct Curl_easy* data, const char* hostname, int port, const struct addrinfo* hints)
{
  addr_ctx->port = port;
#ifndef CURL_DISABLE_SOCKETPAIR
  addr_ctx->sock_pair[0] = CURL_SOCKET_BAD;
  addr_ctx->sock_pair[1] = CURL_SOCKET_BAD;
#endif
  addr_ctx->ref_count = 1;

  DEBUGASSERT(hints);
  addr_ctx->hints = *hints;

  Curl_mutex_init(&addr_ctx->mutx);
#ifdef USE_CURL_COND_T
  Curl_cond_init(&addr_ctx->cond);
#endif

#ifndef CURL_DISABLE_SOCKETPAIR
  /* create socket pair or pipe */
  if (wakeup_create(addr_ctx->sock_pair, FALSE) < 0) {
    addr_ctx->sock_pair[0] = CURL_SOCKET_BAD;
    addr_ctx->sock_pair[1] = CURL_SOCKET_BAD;
    goto err_exit;
  }
#endif
  addr_ctx->sock_error = 0;

  /* Copying hostname string because original can be destroyed by parent
   * thread during gethostbyname execution.
   */
  addr_ctx->hostname = strdup(hostname);
  if (!addr_ctx->hostname)
    goto err_exit;

  return addr_ctx;
}

/*
 * async_win32_destroy() cleans up async resolver data and thread handle.
 */
static void async_win32_destroy(struct Curl_easy* data)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  struct async_win32_request_ctx* addr = win32->addr;

#ifdef USE_HTTPSRR_ARES
  Curl_httpsrr_cleanup(&win32->rr.hinfo);
#endif

  if (win32->addr && win32->addr->thread_hnd != curl_thread_t_null) {
    bool done = TRUE;

    Curl_mutex_acquire(&addr->mutx);
    done = addr->ref_count <= 1;
    Curl_mutex_release(&addr->mutx);
    if (done) {
      Curl_thread_join(&addr->thread_hnd);
      CURL_TRC_DNS(data, "async_win32_destroy, thread joined");
    }
    else {
      /* thread is still running. Detach the thread while mutexed, it will
       * trigger the cleanup when it releases its reference. */
      Curl_thread_destroy(&addr->thread_hnd);
      CURL_TRC_DNS(data, "async_win32_destroy, thread detached");
    }
  }
}

#ifdef USE_HTTPSRR
static void async_win32_httpsrr_cancel(struct async_win32_request_ctx* ctx)
{
  if (ctx->httpsrr.wait_handle == ASYNC_PENDING)
  {
    /* This fires the callback with ERROR_TIMEOUT */
    DNS_STATUS status = Curl_DnsCancelQuery(&ctx->httpsrr.cancel_handle);
    memset(&ctx->httpsrr.cancel_handle, 0, sizeof(ctx->httpsrr.cancel_handle));
  }
}

static bool async_win32_httpsrr_parse_parameter(struct Curl_https_rrinfo* res, DNS_SVCB_PARAM* param)
{
  if (!param) {
    return FALSE;
  }

  switch (param->wSvcParamKey)
  {
  case HTTPS_RR_CODE_MANDATORY:
    CURL_TRC_DNS(NULL, "HTTPS RR MANDATORY left to implement");
    break;
  case HTTPS_RR_CODE_ALPN:
  {
    WORD i;
    if (!param->pAlpn) {
      return FALSE;
    }
    for (i = 0; i < param->pAlpn->cIds; i++)
    {
      Curl_httpsrr_decode_alpn((char*)param->pAlpn->rgIds->pbId, param->pAlpn->rgIds->cBytes, res->alpns);
    }
    break;
  }
  case HTTPS_RR_CODE_NO_DEF_ALPN:
    res->no_def_alpn = param->pUnknown != NULL;
    break;
  case HTTPS_RR_CODE_PORT:
    if (!param->wPort) {
      return FALSE;
    }
    res->port = param->wPort;
    break;
  case HTTPS_RR_CODE_IPV4:
    if (!param->pIpv4Hints) {
      return FALSE;
    }
    res->ipv4hints_len = param->pIpv4Hints->cIps * sizeof(IP4_ADDRESS);
    res->ipv4hints = Curl_memdup(param->pIpv4Hints->rgIps, res->ipv4hints_len);
    break;
  case HTTPS_RR_CODE_ECH:
    if (!param->pUnknown) {
      return FALSE;
    }
    res->echconfiglist_len = param->pUnknown->cBytes;
    res->echconfiglist = Curl_memdup(param->pUnknown->pbSvcParamValue, res->echconfiglist_len);
    break;
  case HTTPS_RR_CODE_IPV6:
    if (!param->pIpv6Hints) {
      return FALSE;
    }
    res->ipv6hints_len = param->pIpv6Hints->cIps * sizeof(IP6_ADDRESS);
    res->ipv6hints = Curl_memdup(param->pIpv6Hints->rgIps, res->ipv6hints_len);
    break;
  default:
    CURL_TRC_DNS(NULL, "HTTPS RR target: %s", hinfo->target);
    break;
  }
  return TRUE;
}

static bool async_win32_httpsrr_parse(struct async_win32_request_ctx* addr_ctx, PDNS_QUERY_RESULT query_results)
{
  PDNS_RECORD record;

  if (query_results->QueryStatus != ERROR_SUCCESS)
  {

  }

  if (!query_results->pQueryRecords) {
    return FALSE;
  }

  for (record = query_results->pQueryRecords; record != NULL; record = record->pNext) {
    size_t i;
    const char* target;

    if (record->Flags.S.Section != DnsSectionAnswer) {
      continue;
    }
    if (record->wType != DNS_TYPE_HTTPS) {
      continue;
    }

    target = record->Data.SVCB.pszTargetName;
    if (target && target[0]) {
      addr_ctx->httpsrr.res.target = strdup(target);
      if (!addr_ctx->httpsrr.res.target) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      CURL_TRC_DNS(data, "HTTPS RR target: %s", hinfo->target);
    }

    addr_ctx->httpsrr.res.priority = record->Data.SVCB.wSvcPriority;
    CURL_TRC_DNS(data, "HTTPS RR priority: %u", addr_ctx->httpsrr.res.priority);

    for (i = 0; i < record->Data.SVCB.cSvcParams; i++) {
      async_win32_httpsrr_parse_parameter(&addr_ctx->httpsrr.res, &record->Data.SVCB.pSvcParams[i]);
    }
  }

  DnsRecordListFree(query_results->pQueryRecords, DnsFreeRecordList);

  async_win32_release(&addr_ctx->httpsrr.wait_handle, ASYNC_ASYNCFINISH);
  return TRUE;
}

static void WINAPI async_win32_httpsrr_cb(PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
  async_win32_httpsrr_parse(pQueryContext, pQueryResults);
}

static bool async_win32_httpsrr_query(struct Curl_easy* data)
{
  struct async_win32_request_ctx* addr_ctx = &data->state.async.win32.request;
  DNS_STATUS status;

  DEBUGASSERT(async_win32_supports_httpsrr);

  status = Curl_DnsQueryEx(&addr_ctx->httpsrr.request.basic, &addr_ctx->httpsrr.result, &addr_ctx->httpsrr.cancel_handle);

  if (status == DNS_REQUEST_PENDING)
  {
    CURL_TRC_DNS(data, "issued HTTPS-RR request for %s", data->conn->host.name);
    return TRUE;
  }

  if (status != ERROR_SUCCESS)
  {
    return FALSE;
  }

  async_win32_httpsrr_parse(addr_ctx, &addr_ctx->httpsrr.result);
  async_win32_release(&addr_ctx->httpsrr.wait_handle, ASYNC_SYNCFINISH);
  return TRUE;
}

static CURLcode async_win32_httpsrr_setup_ctx(struct Curl_easy* data)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  DNS_QUERY_REQUEST* request = &win32->request.httpsrr.request.basic;
  PDNS_QUERY_COMPLETION_ROUTINE callback = async_win32_httpsrr_cb;

  request->Version = DNS_QUERY_REQUEST_VERSION1;
  request->QueryName = win32->request.hostname;
  request->QueryType = DNS_TYPE_HTTPS;
  request->QueryOptions = DNS_QUERY_ADDRCONFIG | DNS_QUERY_PARSE_ALL_RECORDS;
  request->pQueryCompletionCallback = callback;
  request->pQueryContext = &win32->request;

  if (win32->server_cnt)
  {
    DWORD i;
    DNS_QUERY_REQUEST3* extended = &win32->request.httpsrr.request.extended;

    extended->Version = DNS_QUERY_REQUEST_VERSION3;
    extended->cCustomServers = win32->server_cnt;
    extended->pCustomServers = calloc(win32->server_cnt, sizeof(DNS_CUSTOM_SERVER*));

    for (i = 0; i < win32->server_cnt; i++)
    {
      extended->pCustomServers[i].dwServerType = DNS_CUSTOM_SERVER_TYPE_UDP;
      extended->pCustomServers[i].ServerAddr = win32->servers[i];
    }
  }

  win32->request.httpsrr.result.Version = DNS_QUERY_RESULTS_VERSION1;
}
#endif

static void async_win32_cancel(struct async_win32_request_ctx* ctx)
{
  if (ctx->wait_handle == ASYNC_PENDING)
  {
    /* This fires the callback with WSA_E_CANCELLED */
    INT status = Curl_GetAddrInfoExCancel(&ctx->cancel_handle);
    ctx->cancel_handle = NULL;
  }

  async_win32_httpsrr_cancel(ctx);
}

struct Curl_addrinfo* async_win32_parse_addrinfo(PADDRINFOEXW addrinfo)
{
  PADDRINFOEXW ai;
  struct Curl_addrinfo* cafirst = NULL;
  struct Curl_addrinfo* calast = NULL;
  struct Curl_addrinfo* ca;
  size_t ss_size;
  char* canonname = NULL;

  /* traverse the addrinfo list */
  for (ai = addrinfo; ai != NULL; ai = ai->ai_next) {
    size_t namelen;

    if (canonname) {
      curlx_unicodefree(canonname);
    }

    canonname = curlx_convert_wchar_to_UTF8(ai->ai_canonname);
    if (!canonname && ai->ai_canonname) {
      Curl_freeaddrinfo(cafirst);
      cafirst = NULL;
      break;
    }

    /* ignore elements with unsupported address family, */
    /* settle family-specific sockaddr structure size.  */
    if (ai->ai_family == AF_INET)
      ss_size = sizeof(struct sockaddr_in);
#ifdef USE_IPV6
    else if (ai->ai_family == AF_INET6)
      ss_size = sizeof(struct sockaddr_in6);
#endif
    else
      continue;

    /* ignore elements without required address info */
    if (!ai->ai_addr || ai->ai_addrlen <= 0)
      continue;

    /* ignore elements with bogus address size */
    if (ai->ai_addrlen < ss_size)
      continue;

    namelen = canonname ? strlen(canonname) + 1 : 0;
    ca = malloc(sizeof(struct Curl_addrinfo) + ss_size + namelen);
    if (!ca) {
      Curl_freeaddrinfo(cafirst);
      cafirst = NULL;
      break;
    }

    /* copy each structure member individually, member ordering, */
    /* size, or padding might be different for each platform.    */

    ca->ai_flags = ai->ai_flags;
    ca->ai_family = ai->ai_family;
    ca->ai_socktype = ai->ai_socktype;
    ca->ai_protocol = ai->ai_protocol;
    ca->ai_addrlen = (curl_socklen_t)ss_size;
    ca->ai_addr = NULL;
    ca->ai_canonname = NULL;
    ca->ai_next = NULL;

    ca->ai_addr = (void*)((char*)ca + sizeof(struct Curl_addrinfo));
    memcpy(ca->ai_addr, ai->ai_addr, ss_size);

    if (namelen) {
      ca->ai_canonname = (void*)((char*)ca->ai_addr + ss_size);
      memcpy(ca->ai_canonname, canonname, namelen);
    }

    /* if the return list is empty, this becomes the first element */
    if (!cafirst)
      cafirst = ca;

    /* add this element last in the return list */
    if (calast)
      calast->ai_next = ca;
    calast = ca;
  }

  curlx_unicodefree(canonname);

  return cafirst;
}

static bool async_win32_parse_response(struct async_win32_request_ctx* addr_ctx, PADDRINFOEXW addrinfo)
{
  bool result = FALSE;

  if (addrinfo)
  {
    addr_ctx->res = async_win32_parse_addrinfo(addrinfo);
    FreeAddrInfoExW(addrinfo);

#ifdef DEBUGBUILD
    Curl_resolve_test_delay();
#endif

    result = TRUE;
  }

  async_win32_release(&addr_ctx->wait_handle, ASYNC_FINISHED);
  return result;
}

static void CALLBACK async_win32_getaddrinfo_cb(DWORD dwError, DWORD dwBytes, LPWSAOVERLAPPED lpOverlapped) {
  struct async_win32_request_ctx* addr_ctx = (struct async_win32_request_ctx*)lpOverlapped;
  PADDRINFOEXW addrinfo = lpOverlapped->Pointer;

  /* this is unused and always 0 */
  (void)dwBytes;

  if (dwError != ERROR_SUCCESS) {
    addr_ctx->sock_error = (int)dwError;

#ifdef USE_HTTPSRR
    /* Cancel HTTPSRR if normal records fail.
     * If curl starts supporting HTTPSRR only domains,
     * this should check for WSAETIMEDOUT
     */
    async_win32_httpsrr_cancel(addr_ctx);
#endif
  }

  async_win32_parse_response(addr_ctx, addrinfo);
}

/*
 * async_win32_init() starts a new thread that performs the actual
 * resolve. This function returns before the resolve is done.
 *
 * Returns FALSE in case of failure, otherwise TRUE.
 */
static bool async_win32_getaddrinfo(struct Curl_easy* data)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  struct async_win32_request_ctx* addr_ctx = &win32->request;
  PADDRINFOEXW addrinfo = NULL;

  struct timeval* timeout = NULL;
  LPOVERLAPPED overlapped = NULL;
  LPLOOKUPSERVICE_COMPLETION_ROUTINE callback = NULL;
  LPHANDLE handle = NULL;

  /* !checksrc! disable ERRNOVAR 1 */
  int err = ENOMEM;

  DEBUGASSERT(offsetof(struct async_win32_request_ctx, overlapped) == 0);

  if (async_win32_supports_async) {
    timeout = &addr_ctx->timeout;
    overlapped = &addr_ctx->overlapped;
    callback = async_win32_getaddrinfo_cb;
    handle = &addr_ctx->cancel_handle;
  }

  /* in async mode, timeout passing calls the callback with WSAETIMEDOUT */
  err = GetAddrInfoExW(addr_ctx->hostname, addr_ctx->port, NS_DNS,
    NULL, &addr_ctx->hints.basic, &addrinfo,
    timeout, overlapped, callback, handle);

  if (err == WSA_IO_PENDING) {
    CURL_TRC_DNS(data, "resolve request started for of %s:%d", hostname, port);
    return TRUE;
  }

  if (err == NO_ERROR) {
    CURL_TRC_DNS(data, "resolved synchronously for of %s:%d", hostname, port);
    if (!async_win32_parse_response(addr_ctx, addrinfo)) {

    }
    if (addr_ctx->res) {
      return TRUE;
    }
    err = EAI_MEMORY;
  }

  addr_ctx->thread_hnd = Curl_thread_create(getaddrinfo_thread, addr_ctx);

  if (addr_ctx->thread_hnd == curl_thread_t_null) {
    /* The thread never started */
    Curl_mutex_release(&addr_ctx->mutx);
    err = errno;
    goto err_exit;
  }
  else {
#ifdef USE_CURL_COND_T
    /* need to handshake with thread for participation in ref counting */
    Curl_cond_wait(&addr_ctx->cond, &addr_ctx->mutx);
    DEBUGASSERT(addr_ctx->ref_count >= 1);
#endif
    Curl_mutex_release(&addr_ctx->mutx);
  }

#ifdef USE_HTTPSRR_ARES
  if (async_rr_start(data))
    infof(data, "Failed HTTPS RR operation");
#endif

err_exit:
  CURL_TRC_DNS(data, "resolve request failed init: %d", err);
  async_win32_destroy(data);
  CURL_SETERRNO(err);
  return FALSE;
}

static void async_win32_shutdown(struct Curl_easy* data)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  struct async_win32_request_ctx* addr_ctx = &win32->request;

  /* We are no longer interested in wakeups */
  if (addr_ctx->sock_pair[1] != CURL_SOCKET_BAD) {
    addr_ctx->sock_pair[1] = CURL_SOCKET_BAD;
  }

  async_win32_cancel(addr_ctx);
}

/*
 * 'entry' may be NULL and then no data is returned
 */
static CURLcode asyn_win32_await(struct Curl_easy* data,
  struct async_win32_request_ctx* addr_ctx,
  struct Curl_dns_entry** entry)
{
  CURLcode result = CURLE_OK;

  /* not interested in result? cancel, if still running... */
  if (!entry)
    async_win32_shutdown(data);

  CURL_TRC_DNS(data, "resolve, wait for thread to finish");
  async_win32_wait(&addr_ctx->wait_handle);

#ifdef USE_HTTPSRR
  CURL_TRC_DNS(data, "resolve, wait for thread to finish");
  async_win32_wait(&addr_ctx->httpsrr.wait_handle);
#endif

  if (entry) {
    result = Curl_async_is_resolved(data, entry);
    *entry = data->state.async.dns;
  }

  data->state.async.done = TRUE;

  return result;
}

void Curl_async_win32_shutdown(struct Curl_easy* data)
{
  async_win32_shutdown(data);
}

void Curl_async_win32_destroy(struct Curl_easy* data)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;

  if (win32->addr) {
    async_win32_shutdown(data);
  }
  async_win32_destroy(data);
}

/*
 * Curl_async_await()
 *
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved,
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred, or other errors.
 *
 * This is the version for resolves-in-a-thread.
 */
CURLcode Curl_async_await(struct Curl_easy* data,
  struct Curl_dns_entry** entry)
{
  struct async_win32_request_ctx* win32 = &data->state.async.win32.request;
  if (win32->addr)
    return asyn_win32_await(data, win32->addr, entry);
  return CURLE_FAILED_INIT;
}

/*
 * Curl_async_is_resolved() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 */
CURLcode Curl_async_is_resolved(struct Curl_easy* data,
  struct Curl_dns_entry** dns)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  bool done = FALSE;

  DEBUGASSERT(dns);
  *dns = NULL;

  if (data->state.async.done) {
    *dns = data->state.async.dns;
    CURL_TRC_DNS(data, "threaded: is_resolved(), already done, dns=%sfound",
      *dns ? "" : "not ");
    return CURLE_OK;
  }

  DEBUGASSERT(win32->addr);
  if (!win32->addr)
    return CURLE_FAILED_INIT;

  Curl_mutex_acquire(&win32->addr->mutx);
  done = win32->addr->ref_count == 1;
  Curl_mutex_release(&win32->addr->mutx);

  if (!win32->request.wait_handle
#ifdef USE_HTTPSRR
    || !win32->request.wait_handle
#endif
    ) {
    /* poll for name lookup done with exponential backoff up to 250ms */
    /* should be fine even if this converts to 32-bit */
    timediff_t elapsed = curlx_timediff(curlx_now(),
      data->progress.t_startsingle);
    if (elapsed < 0)
      elapsed = 0;

    if (!win32->addr->poll_interval)
      /* Start at 1ms poll interval */
      win32->addr->poll_interval = 1;
    else if (elapsed >= win32->addr->interval_end)
      /* Back-off exponentially if last interval expired  */
      win32->addr->poll_interval *= 2;

    if (win32->addr->poll_interval > 250)
      win32->addr->poll_interval = 250;

    win32->addr->interval_end = elapsed + win32->addr->poll_interval;
    Curl_expire(data, win32->addr->poll_interval, EXPIRE_ASYNC_NAME);
    return CURLE_OK;
  }

  CURLcode result = CURLE_OK;

  data->state.async.done = TRUE;
  Curl_resolv_unlink(data, &data->state.async.dns);

  if (win32->addr->res) {
    data->state.async.dns =
      Curl_dnscache_mk_entry(data, win32->addr->res,
        data->state.async.hostname, 0,
        data->state.async.port, FALSE);
    win32->addr->res = NULL;
    if (!data->state.async.dns)
      result = CURLE_OUT_OF_MEMORY;

#ifdef USE_HTTPSRR_ARES
    if (win32->rr.channel) {
      result = win32->rr.result;
      if (!result) {
        struct Curl_httpsrrinfo* lhrr;
        lhrr = Curl_httpsrr_dup_move(&win32->rr.hinfo);
        if (!lhrr)
          result = CURLE_OUT_OF_MEMORY;
        else
          data->state.async.dns->hinfo = lhrr;
      }
    }
#endif
    if (!result && data->state.async.dns)
      result = Curl_dnscache_add(data, data->state.async.dns);
  }

  if (!result && !data->state.async.dns)
    result = Curl_resolver_error(data);
  if (result)
    Curl_resolv_unlink(data, &data->state.async.dns);
  *dns = data->state.async.dns;
  CURL_TRC_DNS(data, "is_resolved() result=%d, dns=%sfound",
    result, *dns ? "" : "not ");
  async_win32_shutdown(data);
  return result;
}

CURLcode Curl_async_pollset(struct Curl_easy* data, struct easy_pollset* ps)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  CURLcode result = CURLE_OK;

#if !defined(USE_HTTPSRR_ARES) && defined(CURL_DISABLE_SOCKETPAIR)
  (void)ps;
#endif

#ifdef USE_HTTPSRR_ARES
  if (win32->rr.channel) {
    result = Curl_ares_pollset(data, win32->rr.channel, ps);
    if (result)
      return result;
  }
#endif
  if (!win32->addr)
    return result;

#ifndef CURL_DISABLE_SOCKETPAIR
  /* return read fd to client for polling the DNS resolution status */
  if (win32->addr->sock_pair[0] != CURL_SOCKET_BAD) {
    result = Curl_pollset_add_in(data, ps, win32->addr->sock_pair[0]);
  }
#else
  {
    timediff_t milli;
    timediff_t ms = curlx_timediff(curlx_now(), win32->addr->start);
    if (ms < 3)
      milli = 0;
    else if (ms <= 50)
      milli = ms / 3;
    else if (ms <= 250)
      milli = 50;
    else
      milli = 200;
    Curl_expire(data, milli, EXPIRE_ASYNC_NAME);
  }
#endif
  return result;
}

static CURLcode async_win32_set_servers(struct Curl_easy* data, const char* servers)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  size_t len;
  size_t i;

  free(win32->servers);

  if (!async_win32_supports_custom_servers)
  {
    CURL_TRC_DNS(data, "system version doesn't support custom DNS servers");
    servers = NULL;
  }

  if (!servers) {
    win32->server_cnt = 0;
    win32->servers = NULL;
    return CURLE_OK;
  }

  len = strlen(servers);

  if (!len)
  {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  DWORD count = 1;
  for (i = 0; i < len; i++) {
    if (servers[i] == ',') {
      count++;
    }
  }
  win32->server_cnt = count;
  win32->servers = calloc(count, sizeof(SOCKADDR_INET));

  for (i = 0; i < count; i++)
  {
    union
    {
      struct sockaddr sock;
      SOCKADDR_INET addr;
    } addr;

    Curl_str2addr();

    win32->servers[i] = NULL;
  }

  return CURLE_OK;
}

CURLcode Curl_async_win32_set_dns_servers(struct Curl_easy* data)
{
  return async_win32_set_servers(data, data->set.str[STRING_DNS_SERVERS]);
}

static CURLcode async_win32_setup_ctx(struct Curl_easy* data,
  const char* hostname,
  int port,
  int ip_version)
{
  struct async_win32_ctx* win32 = &data->state.async.win32;
  struct async_win32_request_ctx* request = &win32->request;
  int pf = AF_INET;
  timediff_t timeout;

#ifdef CURLRES_IPV6
  if (ip_version != CURL_IPRESOLVE_V4 && Curl_ipv6works(data)) {
    /* The stack seems to be IPv6-enabled */
    pf = ip_version == CURL_IPRESOLVE_V6 ? AF_INET6 : AF_UNSPEC;
  }
#else
  (void)ip_version;
#endif /* CURLRES_IPV6 */

  if (request->wait_handle == ASYNC_PENDING
#ifdef USE_HTTPSRR
    || request->httpsrr.wait_handle == ASYNC_PENDING
#endif
    ) {
    CURL_TRC_DNS(data, "starting new resolve, with previous not cleaned up");
    async_win32_destroy(data);
  }


  free(data->state.async.hostname);

  data->state.async.done = FALSE;
  data->state.async.dns = NULL;
  data->state.async.port = port;
  data->state.async.ip_version = ip_version;
  data->state.async.hostname = strdup(hostname);
  if (!data->state.async.hostname) {
    return CURLE_OUT_OF_MEMORY;
  }

#ifdef CURLDEBUG
  if (getenv("CURL_DNS_SERVER")) {
    async_win32_set_servers(data, getenv("CURL_DNS_SERVER"));
  }
#endif

  curlx_unicodefree(request->hostname);
  free(request->servers);
  free(request->res);

  memset(request, 0, sizeof(*request));

  request->hostname = curlx_convert_UTF8_to_wchar(hostname);
  if (!request->hostname) {
    return CURLE_OUT_OF_MEMORY;
  }

  (void)_itow(port, request->port, 10);

  timeout = Curl_timeleft(data, NULL, TRUE);
  if (timeout < 0) {
    /* already expired! */
    return CURLE_OPERATION_TIMEDOUT;
  }
  if (!timeout)
    timeout = CURL_TIMEOUT_RESOLVE * 1000; /* default name resolve timeout */

  request->timeout.tv_sec = (long)(timeout / 1000);
  request->timeout.tv_usec = (long)(timeout % 1000 * 1000);

  request->hints.basic.ai_flags = AI_ADDRCONFIG;
  request->hints.basic.ai_family = pf;
  if (Curl_conn_get_transport(data, data->conn) == TRNSPRT_TCP) {
    request->hints.basic.ai_socktype = SOCK_STREAM;
    request->hints.basic.ai_protocol = IPPROTO_TCP;
  }
  else {
    request->hints.basic.ai_socktype = SOCK_DGRAM;
    request->hints.basic.ai_protocol = IPPROTO_UDP;
  }

  if (!async_win32_supports_custom_servers) {
    return CURLE_OK;
  }

  if (win32->server_cnt) {
    DWORD i;

    request->servers = calloc(win32->server_cnt, sizeof(ADDRINFO_DNS_SERVER*));

    if (!request->servers)
    {
      return CURLE_OUT_OF_MEMORY;
    }

    for (i = 0; i < win32->server_cnt; i++)
    {
      union
      {
        struct sockaddr* sockaddr;
        SOCKADDR_IN6* v6;
        SOCKADDR_IN* v4;
      } addr;

      request->servers[i].ai_servertype = AI_DNS_SERVER_TYPE_UDP;

      if (win32->servers[i].si_family == AF_INET6) {
        request->servers[i].ai_addrlen = sizeof(SOCKADDR_IN6);
        addr.v6 = &win32->servers[i].Ipv6;
      }
      else {
        request->servers[i].ai_addrlen = sizeof(SOCKADDR_IN);
        addr.v4 = &win32->servers[i].Ipv4;
      }
      request->servers[i].ai_addr = addr.sockaddr;
    }

    request->hints.basic.ai_flags |= AI_EXTENDED | AI_EXCLUSIVE_CUSTOM_SERVERS;
    request->hints.extended.ai_version = 6;
    request->hints.extended.ai_numservers = win32->server_cnt;
    request->hints.extended.ai_servers = request->servers;
  }

#ifdef USE_HTTPSRR
  if (async_win32_supports_httpsrr) {
    return async_win32_httpsrr_setup_ctx(data);
  }
#endif

  return CURLE_OK;
}

/*
 * Curl_async_getaddrinfo() - for getaddrinfo
 */
struct Curl_addrinfo* Curl_async_getaddrinfo(struct Curl_easy* data,
  const char* hostname,
  int port,
  int ip_version,
  int* waitp)
{
  struct Curl_addrinfo* result;

  *waitp = 0; /* default to synchronous response */

  CURL_TRC_DNS(data, "init async resolve of %s:%d", hostname, port);

  if (!async_win32_setup_ctx(data, hostname, port, ip_version))
  {
    failf(data, "async_win32_setup_ctx() failed to parse inputs");
    return NULL;
  }

  /* send a new resolve request */
  if (!async_win32_getaddrinfo(data, hostname, port, ip_version, &hints.basic, &result))
  {
    failf(data, "async_win32_getaddrinfo() failed to resolve");
    return NULL;
  }

  if (data->state.async.win32.request.wait_handle != ASYNC_SYNCFINISH) {
    *waitp = 1; /* expect asynchronous response */
  }

#ifdef USE_HTTPSRR
  if (!async_win32_supports_httpsrr) {
    CURL_TRC_DNS(data, "system version doesn't support HTTPS RR records");
  }
  else if (async_win32_httpsrr_query(data)) {
    if (data->state.async.win32.request.httpsrr.wait_handle != ASYNC_SYNCFINISH) {
      *waitp = 1; /* expect asynchronous response */
    }
  }
#endif

  return result;
}

#endif /* CURLRES_WIN32 */
