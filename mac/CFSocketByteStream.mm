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
