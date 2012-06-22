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

#if !defined(L_SOCKBYTESTREAM_H)
#define L_SOCKBYTESTREAM_H

#include "ByteStream.h"
#include <winsock2.h>

//в случае возникновения проблем с сокетами - выбрасывается исключение с соответствующим кодом ошибки
class LSockByteStream: public LByteStream
{
public:
	LSockByteStream(SOCKET ServerSock)
		:m_ServerSock(ServerSock){};
	virtual unsigned int RawRecv(void* buf, unsigned int buf_len);
	virtual void RawSend(const void* buf, unsigned int data_len);

private:
	SOCKET m_ServerSock;
};
#endif //L_SOCKBYTESTREAM_H
