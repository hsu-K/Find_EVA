#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"

BOOL WINAPI HookInternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_SUCCEED

	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();

		RecordCall(Call::cInternetCheckConnectionA, CTX_NONE, NULL, Hash, RetAddr);
		if (mutInternetCheckConnectionA != NULL) {
			if (mutInternetCheckConnectionA->mutType == MUT_SUCCEED) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return TRUE;
			}
			else if (mutInternetCheckConnectionA->mutType == MUT_FAIL) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return FALSE;
			}
		}
	}

	ret = OgInternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookInternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_SUCCEED

	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();

		RecordCall(Call::cInternetCheckConnectionW, CTX_NONE, NULL, Hash, RetAddr);
		if (mutInternetCheckConnectionW != NULL) {
			if (mutInternetCheckConnectionW->mutType == MUT_SUCCEED) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return TRUE;
			}
			else if (mutInternetCheckConnectionW->mutType == MUT_FAIL) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return FALSE;
			}
		}
	}

	ret = OgInternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}

// not mut
HRESULT WINAPI HookURLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB)
{
	//simple_log_network(HRESULT, URLDownloadToFileW, pCaller, szURL, szFileName, dwReserved, lpfnCB)
	HRESULT ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(szURL);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, szURL, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cURLDownloadToFileW, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgURLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
	//simple_log_network(HINTERNET, InternetOpenA, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cInternetOpenA, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, InternetConnectA, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();

		ContextValue ctxVal;
		size_t widec = strlen(lpszServerName) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, lpszServerName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cInternetConnectA, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, InternetConnectW, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(lpszServerName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, lpszServerName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cInternetConnectW, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, InternetOpenUrlA, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(lpszUrl) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, lpszUrl, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cInternetOpenUrlA, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookHttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, HttpOpenRequestA, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(lpszObjectName) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, lpszObjectName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cHttpOpenRequestA, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookHttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, HttpOpenRequestW, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(lpszObjectName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, lpszObjectName, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cHttpOpenRequestW, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookHttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	//simple_log_network(BOOL, HttpSendRequestA, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
	BOOL ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cHttpSendRequestA, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookHttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	//simple_log_network(BOOL, HttpSendRequestW, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
	BOOL ret;
	BOOL* flag = NULL;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cHttpSendRequestW, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookInternetReadFile(HINTERNET hFile, LPVOID lpBuffersOut, DWORD dwFlags, LPDWORD dwContext)
{
	//simple_log_network(BOOL, InternetReadFile, hFile, lpBuffersOut, dwFlags, dwContext)
	BOOL ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cInternetReadFile, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgInternetReadFile(hFile, lpBuffersOut, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
DNS_STATUS WINAPI HookDnsQuery_A(PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
	//simple_log_network(DNS_STATUS, DnsQuery_A, pszName, wType, Options, pExtra, ppQueryResults, pReserved)
	DNS_STATUS ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(pszName) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, pszName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cDnsQuery_A, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgDnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}
DNS_STATUS WINAPI HookDnsQuery_W(PCWSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
	//simple_log_network(DNS_STATUS, DnsQuery_W, pszName, wType, Options, pExtra, ppQueryResults, pReserved)
	DNS_STATUS ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(pszName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, pszName, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cDnsQuery_W, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgDnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}
INT WSAAPI HookGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult)
{
	//simple_log_network(INT, GetAddrInfoW, pNodeName, pServiceName, pHints, ppResult)
	INT ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = wcslen(pNodeName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, pNodeName, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cGetAddrInfoW, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI HookWSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)
{
	//simple_log_network(int, WSAStartup, wVersionRequired, lpWSAData)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cWSAStartup, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgWSAStartup(wVersionRequired, lpWSAData);
	if (flag) (*flag) = FALSE;
	return ret;
}
hostent* WINAPI Hookgethostbyname(const char* name)
{
	//simple_log_network(hostent*, gethostbyname, name)
	hostent* ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(name) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, name, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cgethostbyname, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = Oggethostbyname(name);
	if (flag) (*flag) = FALSE;
	return ret;
}
SOCKET WSAAPI Hooksocket(int af, int type, int protocol)
{
	//simple_log_network(SOCKET, socket, af, type, protocol)
	SOCKET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::csocket, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogsocket(af, type, protocol);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI Hookconnect(SOCKET s, const sockaddr* name, int namelen)
{
	//simple_log_network(int, connect, s, name, namelen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cconnect, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogconnect(s, name, namelen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI Hooksend(SOCKET s, const char* buf, int len, int flags)
{
	//simple_log_network(int, send, s, buf, len, flags)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::csend, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogsend(s, buf, len, flags);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI Hooksendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
	//simple_log_network(int, sendto, s, buf, len, flags, to, tolen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::csendto, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogsendto(s, buf, len, flags, to, tolen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI Hookrecv(SOCKET s, char* buf, int len, int flags)
{
	//simple_log_network(int, recv, s, buf, len, flags)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::crecv, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogrecv(s, buf, len, flags);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI Hookrecvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
	//simple_log_network(int, recvfrom, s, buf, len, flags, from, fromlen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::crecvfrom, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogrecvfrom(s, buf, len, flags, from, fromlen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI Hookbind(SOCKET s, const sockaddr* addr, int namelen)
{
	//simple_log_network(int, bind, s, addr, namelen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cbind, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = Ogbind(s, addr, namelen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSARecv, s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cWSARecv, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSARecvFrom, s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cWSARecvFrom, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSASend, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cWSASend, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSASendTo, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cWSASendTo, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
SOCKET WSAAPI HookWSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags)
{
	//simple_log_network(SOCKET, WSASocketW, af, type, protocol, lpProtocolInfo, g, dwFlags)
	SOCKET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cWSASocketW, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgWSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}
