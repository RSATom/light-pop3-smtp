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

#include "SSLByteStream.h"

#include "SSLContext.h"

LSSLByteStream::LSSLByteStream(LSockByteStream* SockByteStream)
	:m_SockByteStream(SockByteStream), m_hSSLContext(0)
{
}

LSSLByteStream::LSSLByteStream(LSockByteStream* SockByteStream, LSSLContext* SSLCtxt)
	:m_SockByteStream(SockByteStream), m_hSSLContext(0)
{
	SetSSLContext(SSLCtxt);
}

LSSLByteStream::~LSSLByteStream()
{

}

void LSSLByteStream::SetSSLContext(LSSLContext* SSLCtxt)
{
	m_hSSLContext = SSLCtxt->GetContextHandle();

	/*VERIFY(SEC_E_OK==*/QueryContextAttributes(m_hSSLContext,  SECPKG_ATTR_STREAM_SIZES, &m_StreamSizes)/*)*/;

	m_send.resize(m_StreamSizes.cbHeader+m_StreamSizes.cbMaximumMessage+m_StreamSizes.cbTrailer);

	m_sendBufferDesc.ulVersion = SECBUFFER_VERSION;
	m_sendBufferDesc.pBuffers = m_sendBuffers;
	m_sendBufferDesc.cBuffers = 4;
	m_sendBuffers[STREAM_HEADER].BufferType = SECBUFFER_STREAM_HEADER;
	m_sendBuffers[STREAM_HEADER].pvBuffer   = &m_send[0];
	m_sendBuffers[STREAM_HEADER].cbBuffer   = m_StreamSizes.cbHeader;
	m_sendBuffers[STREAM_DATA].BufferType = SECBUFFER_DATA;
	m_sendBuffers[STREAM_DATA].pvBuffer   = &m_send[0]+m_StreamSizes.cbHeader;
	m_sendBuffers[STREAM_DATA].cbBuffer   = m_StreamSizes.cbMaximumMessage;
	m_sendBuffers[STREAM_TRAILER].BufferType = SECBUFFER_STREAM_TRAILER;
	m_sendBuffers[STREAM_TRAILER].pvBuffer   = &m_send[0]+m_StreamSizes.cbHeader+m_StreamSizes.cbMaximumMessage;
	m_sendBuffers[STREAM_TRAILER].cbBuffer   = m_StreamSizes.cbTrailer;
	m_sendBuffers[EMPTY3].BufferType = SECBUFFER_EMPTY;
	m_sendBuffers[EMPTY3].pvBuffer   = 0;
	m_sendBuffers[EMPTY3].cbBuffer   = 0;

	m_recv.resize(m_StreamSizes.cbHeader+m_StreamSizes.cbMaximumMessage+m_StreamSizes.cbTrailer);
	m_recvBufferDesc.ulVersion = SECBUFFER_VERSION;
	m_recvBufferDesc.pBuffers = m_recvBuffers;
	m_recvBufferDesc.cBuffers = 4;
	m_recvBuffers[EMPTY0].BufferType = SECBUFFER_EMPTY;
	m_recvBuffers[EMPTY0].pvBuffer   = 0;
	m_recvBuffers[EMPTY0].cbBuffer   = 0;
	m_recvBuffers[EMPTY1].BufferType = SECBUFFER_EMPTY;
	m_recvBuffers[EMPTY1].pvBuffer   = 0;
	m_recvBuffers[EMPTY1].cbBuffer   = 0;
	m_recvBuffers[EMPTY2].BufferType = SECBUFFER_EMPTY;
	m_recvBuffers[EMPTY2].pvBuffer   = 0;
	m_recvBuffers[EMPTY2].cbBuffer   = 0;
	m_recvBuffers[EMPTY3].BufferType = SECBUFFER_EMPTY;
	m_recvBuffers[EMPTY3].pvBuffer   = 0;
	m_recvBuffers[EMPTY3].cbBuffer   = 0;

	if(!SSLCtxt->GetHandshakeExtra().empty()){
		m_recvBuffers[STREAM_EXTRA].BufferType = SECBUFFER_EXTRA;
		m_recvBuffers[STREAM_EXTRA].pvBuffer = &m_recv[0];
		memcpy(&m_recv[0], &SSLCtxt->GetHandshakeExtra()[0], SSLCtxt->GetHandshakeExtra().size());
		m_recvBuffers[STREAM_EXTRA].cbBuffer = SSLCtxt->GetHandshakeExtra().size();
	}

}

unsigned int LSSLByteStream::RawRecv(void* buf, unsigned int buf_len)
{
	//ASSERT(m_hSSLContext);
	//1. данных может декодировано больше чем buf_len, т.к. schannel может затребовать еще данные через SEC_E_INCOMPLETE_MESSAGE
	//2. пришедших данных может оказаться больше чем может распаковать schannel, и тогда мы получим SECBUFFER_EXTRA
	if(SECBUFFER_DATA==m_recvBuffers[STREAM_DATA].BufferType&&m_recvBuffers[STREAM_DATA].cbBuffer>0){
		unsigned int copy_bytes = min(m_recvBuffers[STREAM_DATA].cbBuffer, buf_len);
		memcpy(buf, m_recvBuffers[STREAM_DATA].pvBuffer, copy_bytes);
		m_recvBuffers[STREAM_DATA].pvBuffer=static_cast<char*>(m_recvBuffers[STREAM_DATA].pvBuffer)+copy_bytes;
		m_recvBuffers[STREAM_DATA].cbBuffer-=copy_bytes;
		return copy_bytes;
	}

	//ASSERT(!(SECBUFFER_DATA==m_recvBuffers[STREAM_DATA].BufferType&&m_recvBuffers[STREAM_DATA].cbBuffer>0));//не все декодированные данные отданы пользователю

	if(SECBUFFER_EXTRA==m_recvBuffers[STREAM_EXTRA].BufferType){//были данные SECBUFFER_EXTRA, которые еще не пытались дешифровать
		//ASSERT(m_recvBuffers[STREAM_EXTRA].cbBuffer);

		m_recvBuffers[decSTREAM_DATA].BufferType = SECBUFFER_DATA;
		m_recvBuffers[decSTREAM_DATA].pvBuffer=&m_recv[0];
		m_recvBuffers[decSTREAM_DATA].cbBuffer=m_recvBuffers[STREAM_EXTRA].cbBuffer;
		memmove(m_recvBuffers[decSTREAM_DATA].pvBuffer, m_recvBuffers[STREAM_EXTRA].pvBuffer, m_recvBuffers[STREAM_EXTRA].cbBuffer);
		m_recvBuffers[STREAM_EXTRA].BufferType=SECBUFFER_EMPTY;
		m_recvBuffers[STREAM_EXTRA].pvBuffer=0;
		m_recvBuffers[STREAM_EXTRA].cbBuffer=0;
	}
	else{
		unsigned int recv_size = m_SockByteStream->RawRecv(&m_recv[0], m_recv.size());
		m_recvBuffers[decSTREAM_DATA].BufferType = SECBUFFER_DATA;
		m_recvBuffers[decSTREAM_DATA].pvBuffer   = &m_recv[0];
		m_recvBuffers[decSTREAM_DATA].cbBuffer   = recv_size;
	}

	for(SECURITY_STATUS sec_s=SEC_E_INCOMPLETE_MESSAGE;SEC_E_INCOMPLETE_MESSAGE==sec_s;){
		unsigned int in_raw_data_size = m_recvBuffers[decSTREAM_DATA].cbBuffer;
	
		//ASSERT(SECBUFFER_DATA==m_recvBuffers[decSTREAM_DATA].BufferType);
		m_recvBuffers[EMPTY1].BufferType = SECBUFFER_EMPTY;
		m_recvBuffers[EMPTY1].pvBuffer   = 0;
		m_recvBuffers[EMPTY1].cbBuffer   = 0;
		m_recvBuffers[EMPTY2].BufferType = SECBUFFER_EMPTY;
		m_recvBuffers[EMPTY2].pvBuffer   = 0;
		m_recvBuffers[EMPTY2].cbBuffer   = 0;
		m_recvBuffers[EMPTY3].BufferType = SECBUFFER_EMPTY;
		m_recvBuffers[EMPTY3].pvBuffer   = 0;
		m_recvBuffers[EMPTY3].cbBuffer   = 0;

		sec_s=DecryptMessage(m_hSSLContext, &m_recvBufferDesc, 0, NULL);
		//VERIFY(SEC_E_OK==sec_s||SEC_E_INCOMPLETE_MESSAGE==sec_s);
		switch(sec_s){
			case SEC_E_OK:{//декодирование прошло успешно. разберемся с результатом
				//ASSERT(SECBUFFER_DATA==m_recvBuffers[STREAM_DATA].BufferType&&m_recvBuffers[STREAM_DATA].cbBuffer>0);
				//чтоб не писать 2 раза одно и то же сделаем рекурсивный вызов(должен сработать первый блок функции)
				return RawRecv(buf, buf_len);
				break;
			}
			case SEC_E_INCOMPLETE_MESSAGE:{ //мало данных
				//ASSERT(SECBUFFER_MISSING==m_recvBuffers[STREAM_DATA].BufferType&&m_recvBuffers[STREAM_DATA].cbBuffer>0);
				unsigned int recv_bytes = m_recv.size()-in_raw_data_size; //ASSERT(recv_bytes>0);

				in_raw_data_size += m_SockByteStream->RawRecv(&m_recv[0]+in_raw_data_size, recv_bytes);
			
				m_recvBuffers[decSTREAM_DATA].BufferType = SECBUFFER_DATA;
				m_recvBuffers[decSTREAM_DATA].pvBuffer = &m_recv[0];
				m_recvBuffers[decSTREAM_DATA].cbBuffer = in_raw_data_size;

				break;
			}
			case SEC_E_CONTEXT_EXPIRED: //на той стороне закрыли подключение
				//Call EncryptMessage, passing in an empty input buffer.
				//Send the output buffers from the EncryptMessage call to the remote party (the sender of the decrypted message).
				//Delete the security context by calling the DeleteSecurityContext function.
			case SEC_E_MESSAGE_ALTERED://сообщение не прошло проверку?
			case SEC_I_RENEGOTIATE://опять надо поздороваться
			default:
				throw SEC_E(sec_s);
		}

	}

	//ASSERT(false);//сюда доходить не должно
	return 0;
}

void LSSLByteStream::RawSend(const void* buf, unsigned int data_len)
{
	//ASSERT(m_hSSLContext);

	while(data_len){
		unsigned int enc_size = min(m_StreamSizes.cbMaximumMessage, data_len);
	
		//m_sendBuffers[STREAM_HEADER].pvBuffer=&m_send[0];//никогда не меняется
		//m_sendBuffers[STREAM_HEADER].cbBuffer=m_StreamSizes.cbHeader;//никогда не меняется
		//m_sendBuffers[STREAM_DATA].pvBuffer=&m_send[0]+m_StreamSizes.cbHeader;//никогда не меняется
		m_sendBuffers[STREAM_DATA].cbBuffer=enc_size;
		m_sendBuffers[STREAM_TRAILER].pvBuffer=static_cast<char*>(m_sendBuffers[STREAM_DATA].pvBuffer)+m_sendBuffers[STREAM_DATA].cbBuffer;
		//m_sendBuffers[STREAM_TRAILER].cbBuffer=m_StreamSizes.cbTrailer;//никогда не меняется
		memcpy(m_sendBuffers[STREAM_DATA].pvBuffer, buf, enc_size);
	
		SECURITY_STATUS sec_s=EncryptMessage(m_hSSLContext, 0, &m_sendBufferDesc, 0);
		//ASSERT(SEC_E_OK==sec_s);
	
		m_SockByteStream->RawSend(static_cast<char*>(m_sendBuffers[STREAM_HEADER].pvBuffer),
		                         m_sendBuffers[STREAM_HEADER].cbBuffer+
		                         m_sendBuffers[STREAM_DATA].cbBuffer+
		                         m_sendBuffers[STREAM_TRAILER].cbBuffer);
		//ASSERT(0==m_sendBuffers[EMPTY3].cbBuffer);

		buf=static_cast<const char*>(buf)+enc_size;
		data_len-=enc_size;
	
	}
}