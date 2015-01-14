/*******************************************************************************
* Copyright © 2008-2015, Sergey Radionov <rsatom_gmail.com>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*   1. Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
*   2. Redistributions in binary form must reproduce the above copyright notice,
*      this list of conditions and the following disclaimer in the documentation
*      and/or other materials provided with the distribution.

* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#if !defined(W_SOCK_HELPERS_H)
#define W_SOCK_HELPERS_H

#include <winsock2.h>

//////////////////////////////////////////////////////////////////////
// GetBinAddr
//////////////////////////////////////////////////////////////////////
u_long GetBinAddr(const char* Host);

//////////////////////////////////////////////////////////////////////
// class UseWinSock
//////////////////////////////////////////////////////////////////////
class UseWinSock
{
	void Init(WORD wVersionRequested)
	{
		ZeroMemory(&wsaData, sizeof(wsaData));
		WSAStartupError = WSAStartup( wVersionRequested, &wsaData );
	}

public:
	UseWinSock(BYTE bVersionMajorRequested, BYTE bVersionMinorRequested)
	{
		Init( MAKEWORD(bVersionMajorRequested, bVersionMinorRequested) );
	}
	UseWinSock(WORD wVersionRequested)
	{
		Init( wVersionRequested );
	}

	operator bool(){return WSAStartupError==0;}
	const ::WSADATA& WSADATA(){return wsaData;}

	~UseWinSock(){if(0==WSAStartupError) /*VERIFY(0==*/WSACleanup()/*)*/;}

private:
	int WSAStartupError;
	::WSADATA wsaData;
};

//////////////////////////////////////////////////////////////////////
// class AutoCloseSocket
//////////////////////////////////////////////////////////////////////
class AutoCloseSocket
{
public:
	AutoCloseSocket(SOCKET hSock)
		:m_hSock(hSock){}
	~AutoCloseSocket() {closesocket(m_hSock);}
private:
	const SOCKET m_hSock;
};

//////////////////////////////////////////////////////////////////////
// class AutoShutdownConnection
//////////////////////////////////////////////////////////////////////
class AutoShutdownConnection
{
public:
	AutoShutdownConnection(SOCKET hSock, int how = SD_BOTH)
		:m_hSock(hSock), m_HowToShutdown(how){}
	~AutoShutdownConnection() {shutdown(m_hSock, m_HowToShutdown);}
private:
	const SOCKET m_hSock;
	const int    m_HowToShutdown;
};

#endif //W_SOCK_HELPERS_H
