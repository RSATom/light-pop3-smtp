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

#if !defined(L_SSLBYTESTREAM_H)
#define L_SSLBYTESTREAM_H

#include <vector>

#include "SockByteStream.h"

#ifndef SECURITY_WIN32
	#define SECURITY_WIN32 1
	#include <security.h>
#endif
class LSSLContext;//#include "SSLContext.h"

class LSSLByteStream : public LByteStream
{
public:
	//исключения касающиеся SSPI.
	struct SEC_E //тип выбрасываемых исключений
	{
		SEC_E(SECURITY_STATUS e):error(e){}
		SECURITY_STATUS error;
	};

	LSSLByteStream(LSockByteStream* SockByteStream);
	LSSLByteStream(LSockByteStream* SockByteStream, LSSLContext* SSLCtxt);
	~LSSLByteStream();

	void SetSSLContext(LSSLContext* SSLCtxt);
	//Помимо SSPI исключений могут быть выброшены LSockByteStream исключения
	virtual unsigned int RawRecv(void* buf, unsigned int buf_len);
	//Помимо SSPI исключений могут быть выброшены LSockByteStream исключения
	virtual void RawSend(const void* buf, unsigned int data_len);

private:
	LSockByteStream* m_SockByteStream;
	CtxtHandle* m_hSSLContext;
	SecPkgContext_StreamSizes m_StreamSizes;

	enum{STREAM_HEADER=0, STREAM_DATA=1, STREAM_TRAILER=2,	STREAM_EXTRA=3,
	     EMPTY0=0, EMPTY1=1, EMPTY2=2, EMPTY3=3,
	     decSTREAM_DATA=0};
	SecBufferDesc     m_sendBufferDesc;
	SecBuffer         m_sendBuffers[4];
	std::vector<BYTE> m_send;

	SecBufferDesc     m_recvBufferDesc;
	SecBuffer         m_recvBuffers[4];
	std::vector<BYTE> m_recv;
};

typedef LSSLByteStream::SEC_E LSSL_SEC_E;

#endif //L_SSLBYTESTREAM_H
