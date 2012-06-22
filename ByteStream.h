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

#if !defined(L_BYTE_STREAM_H)
#define L_BYTE_STREAM_H

class LByteStream
{
public:
	struct BS_EOF{};//eof exception.
	//some other implementation specific exceptions are possible.

	virtual unsigned int RawRecv(void* buf, unsigned int buf_len)=0;
	virtual void RawSend(const void* buf, unsigned int data_len)=0;
};
typedef LByteStream::BS_EOF LBS_EOF;

#endif //L_BYTE_STREAM_H
