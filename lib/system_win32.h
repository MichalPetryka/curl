#ifndef HEADER_CURL_SYSTEM_WIN32_H
#define HEADER_CURL_SYSTEM_WIN32_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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

#include "curl_setup.h"

#ifdef _WIN32

#include <curl/curl.h>

extern LARGE_INTEGER Curl_freq;
extern bool Curl_isVistaOrGreater;

CURLcode Curl_win32_init(long flags);
void Curl_win32_cleanup(long init_flags);

#ifndef HAVE_IF_NAMETOINDEX
/* We use our own typedef here since some headers might lack this */
typedef unsigned int(WINAPI *IF_NAMETOINDEX_FN)(const char *);

/* This is used instead of if_nametoindex if available on Windows */
extern IF_NAMETOINDEX_FN Curl_if_nametoindex;
#endif

#ifdef CURLRES_WIN32
/* We use our own typedef here since some headers might lack this */
typedef INT(WSAAPI* GETADDRINFOEXCANCEL_FN)(LPHANDLE);

typedef BOOL(WINAPI* WAITONADDRESS_FN)(volatile VOID*, PVOID, SIZE_T, DWORD);

typedef VOID(WINAPI* WAKEBYADDRESSALL_FN)(PVOID);

typedef DNS_STATUS(WINAPI* DNSQUERYEX_FN)(PDNS_QUERY_REQUEST, PDNS_QUERY_RESULT, PDNS_QUERY_CANCEL);

typedef DNS_STATUS(WINAPI* DNSCANCELQUERY_FN)(PDNS_QUERY_CANCEL);

extern GETADDRINFOEXCANCEL_FN Curl_GetAddrInfoExCancel;

extern WAITONADDRESS_FN Curl_WaitOnAddress;

extern WAKEBYADDRESSALL_FN Curl_WakeByAddressAll;

extern DNSQUERYEX_FN Curl_DnsQueryEx;

extern DNSCANCELQUERY_FN Curl_DnsCancelQuery;
#endif
#else  /* _WIN32 */
#define Curl_win32_init(x) CURLE_OK
#endif /* !_WIN32 */

#endif /* HEADER_CURL_SYSTEM_WIN32_H */
