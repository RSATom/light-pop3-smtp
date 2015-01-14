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
