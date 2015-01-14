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

#include "SSLContext.h"

#include <vector>

#ifdef UNDER_CE
#include <schnlsp.h>
#else
#include <schannel.h>
#endif

LSSLContext::LSSLContext()
	:m_ReqContextAttr(ISC_REQ_CONFIDENTIALITY|ISC_REQ_MANUAL_CRED_VALIDATION|ISC_REQ_STREAM|ISC_REQ_ALLOCATE_MEMORY)
{
	memset(&m_hUserCred, 0, sizeof(m_hUserCred));
	memset(&m_hContext, 0, sizeof(m_hContext));
}

LSSLContext::~LSSLContext()
{
	BYTE stub1[sizeof(m_hContext)]; memset(stub1, 0, sizeof(stub1));
	if(0!=memcmp(&m_hContext, stub1, sizeof(m_hContext))){//возможно глупость так проверять на инициализированность
		/*VERIFY(SEC_E_OK==*/DeleteSecurityContext(GetContextHandle())/*)*/;
		memset(&m_hContext, 0, sizeof(m_hContext));
	}

	BYTE stub2[sizeof(m_hUserCred)]; memset(stub2, 0, sizeof(stub2));
	if(0!=memcmp(&m_hUserCred, stub2, sizeof(m_hUserCred))){//возможно глупость так проверять на инициализированность
		/*VERIFY(SEC_E_OK==*/FreeCredentialsHandle(&m_hUserCred)/*)*/;
		memset(&m_hUserCred, 0, sizeof(m_hUserCred));
	}
}

void LSSLContext::AcquireCredentials()
{
	//SSPI:инициализация удостоверения
	//параметны получаемого удостоверения пользователя
	SCHANNEL_CRED credData;
	ZeroMemory(&credData, sizeof(credData));
	credData.dwVersion = SCHANNEL_CRED_VERSION;

	//получение дискриптора удостоверения пользователя
	SECURITY_STATUS sec_s = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_OUTBOUND, 0, &credData, 0, 0, &m_hUserCred, &m_UserCredExpiry);
	//ASSERT(SEC_E_OK==sec_s);
}

void LSSLContext::Handshake(LSockByteStream* SockByteStream, const TCHAR* TargetName)
{
	SecPkgInfo* PkgInfo;
	/*VERIFY(SEC_E_OK==*/QuerySecurityPackageInfo(UNISP_NAME, &PkgInfo)/*)*/;
	std::vector<BYTE> SockDataBuf(PkgInfo->cbMaxToken);
	FreeContextBuffer(PkgInfo);

	//SSPI:HandShake
	SecBufferDesc InBufferDesc;
	SecBuffer     InBuffers[2];
	InBufferDesc.ulVersion = SECBUFFER_VERSION;
	InBufferDesc.pBuffers = InBuffers;
	InBufferDesc.cBuffers = 2;

	SecBufferDesc OutBufferDesc;
	SecBuffer     OutBuffers[1];
	OutBufferDesc.ulVersion = SECBUFFER_VERSION;
	OutBufferDesc.pBuffers = OutBuffers;
	OutBufferDesc.cBuffers = 1;

	//первичное обращение об инициализации контекста
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].pvBuffer   = NULL;
	OutBuffers[0].cbBuffer   = 0;
	SECURITY_STATUS sec_s = InitializeSecurityContext(&m_hUserCred, 0, const_cast<TCHAR*>(TargetName),
		m_ReqContextAttr, 0, 0, NULL, 0, &m_hContext, &OutBufferDesc, &m_ContextAttr, &m_ContextExpiry);
	//ASSERT(SEC_E_OK==sec_s||SEC_I_CONTINUE_NEEDED==sec_s);

	unsigned int SockDataSize=0;
	bool WasExtra=false;
	while(SEC_I_CONTINUE_NEEDED==sec_s){
		//оба поля должны быть либо указаны либо не указаны, т.к. иначе не совсем понятно что это означает
		//ASSERT((OutBuffers[0].pvBuffer&&OutBuffers[0].cbBuffer)||(!OutBuffers[0].pvBuffer&&!OutBuffers[0].cbBuffer));
		//отсылаем только если есть что отсылать
		if(OutBuffers[0].pvBuffer&&OutBuffers[0].cbBuffer){
			//ASSERT(OutBuffers[0].pvBuffer);
			//ASSERT(OutBuffers[0].cbBuffer);
		
			//WS: отправим обработанные SCHANNEL данные
			SockByteStream->RawSend(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
		
			//SSPI:освободим выделенную SCHANNEL память
			FreeContextBuffer(OutBuffers[0].pvBuffer);
		}
	
		//OutBuffers[0].BufferType=SECBUFFER_EMPTY; OutBuffers[0].pvBuffer=0; OutBuffers[0].cbBuffer=0;//нет необходимости
		do{
			//ASSERT(SockDataBuf.size()>SockDataSize);

			//WS:получим ответ сервера (или его часть)
			if(!WasExtra){
				SockDataSize+= SockByteStream->RawRecv(&SockDataBuf[SockDataSize], SockDataBuf.size()-SockDataSize);
			}
			else{
				//пропустим 1 получение данных, т.к. в SECBUFFER_EXTRA может быть полный пакет,
				//и как следствие сервер ничего уже посылать не будет.
				//если же пакет все же не полный то получим SEC_E_INCOMPLETE_MESSAGE,
				//и просто выполним лишнюю итерацию.
				WasExtra=false;
			}

			//SSPI:передадим этот ответ в InitializeSecurityContext, и в случае если он скажет что надо еще данных -
			//опять запросим данные с сервера. и так до тех пор пока SCHANNEL не скажет "хватит".
			InBuffers[0].BufferType = SECBUFFER_TOKEN;
			InBuffers[0].pvBuffer   = &SockDataBuf[0];
			InBuffers[0].cbBuffer   = SockDataSize;
			InBuffers[1].BufferType = SECBUFFER_EMPTY;
			InBuffers[1].pvBuffer   = NULL;
			InBuffers[1].cbBuffer   = 0;

			sec_s = InitializeSecurityContext(&m_hUserCred, &m_hContext, const_cast<TCHAR*>(TargetName),
				m_ReqContextAttr, 0, 0, &InBufferDesc, 0, 0, &OutBufferDesc, &m_ContextAttr, &m_ContextExpiry);
		}while(SEC_E_INCOMPLETE_MESSAGE==sec_s);
	
		//ASSERT(SEC_E_OK==sec_s||SEC_I_CONTINUE_NEEDED==sec_s);

		//может быть SECBUFFER_EXTRA
		//ASSERT(SECBUFFER_EXTRA!=InBuffers[0].BufferType);//такого вроде не должно быть
		if(SECBUFFER_EXTRA==InBuffers[1].BufferType){
			WasExtra=true;
			if(SEC_I_CONTINUE_NEEDED==sec_s){
				//Handshake еще не завершен. просто сервер выслал больше данных чем нужно было на данном шаге.
				//переносим эти данные на следующую итерацию
				memmove(&SockDataBuf[0],
						((BYTE*)InBuffers[0].pvBuffer)+InBuffers[0].cbBuffer-InBuffers[1].cbBuffer,
				        InBuffers[1].cbBuffer);
				SockDataSize=InBuffers[1].cbBuffer;
			}
			else{
				//если Handshake уже завершен, значит SECBUFFER_EXTRA относится уже к основному протоколу обмена.
				//значит нужно сохранить эту информацию во временном хранилище.
				m_HandshakeExtra.insert(m_HandshakeExtra.end(),
					((BYTE*)InBuffers[0].pvBuffer)+InBuffers[0].cbBuffer-InBuffers[1].cbBuffer,
					((BYTE*)InBuffers[0].pvBuffer)+InBuffers[0].cbBuffer);
				SockDataSize=0;
			}
		}
		else{
			SockDataSize=0;
		}
	}

	//ASSERT(0==OutBuffers[0].pvBuffer);//по идее не должно быть выделенной памяти.
}

void LSSLContext::Shutdown(LSockByteStream* SockByteStream, const TCHAR* TargetName)
{
	//SSPI: отключение от сервера
	//сначала выставим нужный статус у контекста
	DWORD ShutdownToken = SCHANNEL_SHUTDOWN;
	SecBufferDesc ShutDownBufferDesc;
	SecBuffer     ShutDownBuffers[1];
	ShutDownBufferDesc.cBuffers = 1;
	ShutDownBufferDesc.pBuffers = ShutDownBuffers;
	ShutDownBufferDesc.ulVersion = SECBUFFER_VERSION;
	ShutDownBuffers[0].pvBuffer   = &ShutdownToken;
	ShutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
	ShutDownBuffers[0].cbBuffer   = sizeof(ShutdownToken);

	//VERIFY(SEC_E_OK==ApplyControlToken(GetContextHandle(), &ShutDownBufferDesc));

	//затем получим данные для отправки
	ShutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
	ShutDownBuffers[0].pvBuffer   = 0;
	ShutDownBuffers[0].cbBuffer   = 0;

	/*VERIFY(SEC_E_OK==*/InitializeSecurityContext(&m_hUserCred, GetContextHandle(), const_cast<TCHAR*>(TargetName),
		                                       m_ReqContextAttr, 0, 0, 0, 0, 0,
		                                       &ShutDownBufferDesc, &m_ContextAttr, &m_ContextExpiry)/*)*/;

	//ASSERT(ShutDownBuffers[0].pvBuffer&&ShutDownBuffers[0].cbBuffer);

	//WS: отправим обработанные SCHANNEL данные
	SockByteStream->RawSend(ShutDownBuffers[0].pvBuffer, ShutDownBuffers[0].cbBuffer);

	FreeContextBuffer(ShutDownBuffers[0].pvBuffer);
	ShutDownBuffers[0].pvBuffer=0;
	ShutDownBuffers[0].cbBuffer=0;
}
