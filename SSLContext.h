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

#if !defined(L_SSLCONTEXT_H)
#define L_SSLCONTEXT_H

#include "SockByteStream.h"

#include <vector>

#ifndef SECURITY_WIN32
#	define SECURITY_WIN32 1
#	include <security.h>
#endif

class LSSLContext
{
public:
	LSSLContext();
	~LSSLContext();

	void AcquireCredentials();
	void Handshake(LSockByteStream* SockByteStream, const TCHAR* TargetName);
	void Shutdown(LSockByteStream* SockByteStream, const TCHAR* TargetName);

	CtxtHandle* GetContextHandle() {return &m_hContext;}

	const std::vector<BYTE>& GetHandshakeExtra() const {return m_HandshakeExtra;};

private:
	ULONG m_ReqContextAttr;
	CredHandle m_hUserCred;
	TimeStamp  m_UserCredExpiry;

	CtxtHandle m_hContext;
	TimeStamp  m_ContextExpiry;
	ULONG m_ContextAttr;

	std::vector<BYTE> m_HandshakeExtra;
};

#endif //L_SSLCONTEXT_H
