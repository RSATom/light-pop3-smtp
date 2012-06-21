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

#import "../ByteStream.h"
#import <CoreFoundation/CoreFoundation.h>

class CFSocketByteStream : public LByteStream
{
public:
    struct CFS_IO_ERROR{};

    CFSocketByteStream()
        :m_inStream(0), m_outStream(0){}
    ~CFSocketByteStream()
        { Close(); }

    bool Open(const CFStringRef& hostName, unsigned short Port, bool UseSSL = false);
    bool Open(const char* hostName, unsigned short Port, bool UseSSL = false);
    void Close();

    virtual unsigned int RawRecv(void* buf, unsigned int buf_len);
    virtual void RawSend(const void* buf, unsigned int data_len);

private:
    static const CFStringRef sslSettingsKeys[];
    static const CFStringRef sslSettingsVals[];
    static const CFIndex     sslKeyCount;

    CFReadStreamRef  m_inStream;
    CFWriteStreamRef m_outStream;
};

typedef CFSocketByteStream::CFS_IO_ERROR CFS_IO_ERROR;
