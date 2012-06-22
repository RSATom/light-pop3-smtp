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

