/*****************************************************************************
* Copyright (c) 2008-2012 Sergey Radionov <rsatom_gmail.com>
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2.1 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program; if not, write to the Free Software Foundation,
* Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
*****************************************************************************/

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
