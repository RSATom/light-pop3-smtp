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

#include "stdafx.h"

#include <iostream>

#include <WSockHelpers.h>
#include <SockByteStream.h>
#include <SSLContext.h>
#include <SSLByteStream.h>
#include <Smtp.h>

inline std::wstring to_wstring(const std::string& str)
{
	const std::string::value_type* s = str.c_str();

	int convert_size = ::MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
	std::wstring utf16_str(convert_size, ' ');
	convert_size = ::MultiByteToWideChar(CP_ACP, 0, s, -1, &utf16_str[0], utf16_str.size());
	utf16_str.resize(utf16_str.size()-1);
	return utf16_str;
};

int _tmain(int argc, _TCHAR* argv[])
{
	const std::string    SMTPServer = "smtp.gmail.com";
	const bool           UseSSL     = true;
	const unsigned short SMTPPort   = UseSSL ? 465 : 25;

	const std::string    SMTPUser   = "vasya.pupkin@gmail.com";
	const std::string    SMTPPass   = "password";
	const std::string    SMTPFrom   = SMTPUser;
	const std::string    SMTPTo     = SMTPUser;

	UseWinSock ws(2, 2);
	if( !ws )
		return -1;

	u_long srvr_bin_addr = GetBinAddr(SMTPServer.c_str());
	if( INADDR_NONE==srvr_bin_addr ) {
		return -1;
	}

	sockaddr_in ssock_addr;
	ssock_addr.sin_family = AF_INET;
	ssock_addr.sin_port = htons(SMTPPort);
	ssock_addr.sin_addr.s_addr = srvr_bin_addr;

	SOCKET hServerSock = socket(AF_INET, SOCK_STREAM, 0);
	if( INVALID_SOCKET == hServerSock )
		return -1;
	AutoCloseSocket CloseSocket(hServerSock);

	int ws_ret = connect(hServerSock, (sockaddr *)&ssock_addr, sizeof(ssock_addr));
	if( SOCKET_ERROR != ws_ret ) {
		AutoShutdownConnection ShutdownConnection(hServerSock, SD_BOTH);
		std::cout<<"Connected to: "<<SMTPServer<<" port:"<<SMTPPort<<std::endl;

		try{
			LSockByteStream ss(hServerSock);
			LSSLContext SSLCtx;//in case we will need SSL
			LSSLByteStream ssls(&ss);//in case we will need SSL
			if( UseSSL ) {
				SSLCtx.AcquireCredentials();
				SSLCtx.Handshake(&ss, to_wstring(SMTPServer).c_str() );
				ssls.SetSSLContext(&SSLCtx);
			}

			//SMTP protocol conversation
			LSmtp smtp( UseSSL ? (LByteStream*)&ssls : (LByteStream*)&ss );
			smtp.Greeting();
			std::cout<<"Server greeting: "<<smtp.GetReply();
			std::vector<std::string> Extensions;
			smtp.EHLO("anonymous", &Extensions);
			if( smtp.AUTH_PLAIN(std::string(), SMTPUser, SMTPPass) ) {
				std::cout<<"User name: "<<SMTPUser<<std::endl;
				std::cout<<std::endl;

				std::string Message;
				Message += "from: "+SMTPFrom+"\r\n";
				Message += "to:"+SMTPTo+"\r\n";
				Message += "subject: Hello world!\r\n";
				Message += "\r\n";
				Message += "It works!.\r\n";
				Message += ".\r\n";
				std::cout<<"Trying to send message: "<<std::endl;
				std::cout<<std::endl<<Message<<std::endl;

				if( smtp.MAIL(SMTPFrom)&&
				    smtp.RCPT(SMTPTo)&&
				    smtp.DATA(&Message[0], Message.size()) )
				{
					std::cout<<"Success!"<<std::endl;
				} else {
					std::cout<<"Failed!"<<std::endl;
				}
			}
			smtp.QUIT();
		}
		catch(LSmtp::BAD_SMTP_PROTOCOL&){//some problem with SMTP
			return -1;
		}
		catch(LBS_EOF&){//connection closed.
			return -1;
		}
		catch(LSSL_SEC_E&){//some problems with ssl.
			return -1;
		}
		catch(int){//some problem with socket io.
			return -1;
		}
	}
	else
		return -1;

	return 0;
}

