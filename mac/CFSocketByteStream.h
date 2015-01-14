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
