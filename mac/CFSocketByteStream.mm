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

#import "CFSocketByteStream.h"

#import <CoreFoundation/CFStream.h>

const CFStringRef CFSocketByteStream::sslSettingsKeys[] = {kCFStreamSSLLevel};
const CFStringRef CFSocketByteStream::sslSettingsVals[] = {kCFStreamSocketSecurityLevelNegotiatedSSL};
const CFIndex     CFSocketByteStream::sslKeyCount       = sizeof(CFSocketByteStream::sslSettingsKeys)/sizeof(CFSocketByteStream:: sslSettingsKeys[0]);

bool CFSocketByteStream::Open(const char* hostName, unsigned short Port, bool UseSSL)
{
    CFStringRef cfHostName = CFStringCreateWithCString(kCFAllocatorDefault, hostName, kCFStringEncodingUTF8);
    if (cfHostName) {
        return Open(cfHostName, Port, UseSSL);
    }
    return false;
}

bool CFSocketByteStream::Open(const CFStringRef& hostName, unsigned short Port, bool UseSSL)
{
    Close();

    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, hostName, Port, &m_inStream, &m_outStream);

    Boolean br;

    if(UseSSL){
        CFDictionaryRef sslSettings = CFDictionaryCreate(kCFAllocatorDefault, (const void**)&sslSettingsKeys, (const void**)&sslSettingsVals, sslKeyCount, NULL, NULL);
        br = CFReadStreamSetProperty(m_inStream, kCFStreamPropertySSLSettings, sslSettings);
    }

    return FALSE != CFWriteStreamOpen(m_outStream) && FALSE != CFReadStreamOpen(m_inStream);
}

void CFSocketByteStream::Close()
{
    if( m_outStream ){
        CFWriteStreamClose(m_outStream);
        m_outStream = 0;
    }

    if( m_inStream ){
        CFReadStreamClose(m_inStream);
        m_inStream = 0;
    }
}

unsigned int CFSocketByteStream::RawRecv(void* buf, unsigned int buf_len)
{
    CFIndex rc = CFReadStreamRead(m_inStream, (UInt8*)buf, (CFIndex)buf_len);
    switch( rc ) {
        case 0:
            throw BS_EOF();
        case -1:
            throw CFS_IO_ERROR();
    }
    return rc;
}

void CFSocketByteStream::RawSend(const void* buf, unsigned int data_len)
{
    CFIndex wc = CFWriteStreamWrite(m_outStream, (UInt8*)buf, (CFIndex)data_len);
    switch( wc ) {
        case 0:
            throw BS_EOF();
        case -1:
            throw CFS_IO_ERROR();
    }
}
