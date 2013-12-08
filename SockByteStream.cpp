/*****************************************************************************
* Copyright (c) 2008-2012 Sergey Radionov <rsatom_gmail.com>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the Sergey Radionov aka RSATom nor the
*       names of project contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#include "SockByteStream.h"

unsigned int LSockByteStream::RawRecv(void* buf, unsigned int buf_len)
{
	int ret = recv(m_ServerSock, static_cast<char*>(buf), buf_len, 0);
	switch(ret){
		case SOCKET_ERROR:{
			//какая то ошибка - выбрасываем исключение с кодом ошибки
			throw WSAGetLastError();
			break;
		}
		case 0:{//MSDN:If the socket is connection oriented and the remote side has shut down the connection gracefully, and all data has been received, a recv will complete immediately with zero bytes received
			//на том конце закрыли канал - надо как то известить вызывающего об этом
			//фактически EOF
			throw LBS_EOF();
			break;
		}
	}
	//ASSERT(ret>0);
	return ret;
}

void LSockByteStream::RawSend(const void* buf, unsigned int data_len)
{
	//send может отправить меньше чем указано, поэтому нужно за этим следить
	unsigned int offset=0;
	do{
		int ret = send(m_ServerSock, static_cast<const char*>(buf)+offset, data_len-offset, 0);
		if(SOCKET_ERROR==ret){
			//какая то ошибка - выбрасываем исключение с кодом ошибки
			throw WSAGetLastError();
		}
		//ASSERT(ret>0);
		offset+=ret;
	}
	while(offset<data_len);
}

