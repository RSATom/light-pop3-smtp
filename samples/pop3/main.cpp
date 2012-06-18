#include "stdafx.h"

#include <iostream>

#include <WSockHelpers.h>
#include <SockByteStream.h>
#include <SSLContext.h>
#include <SSLByteStream.h>
#include <Pop3.h>

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
	const std::string    Pop3Server = "pop.gmail.com";
	const bool           UseSSL     = true;
	const unsigned short Pop3Port   = UseSSL ? 995 : 110;

	const std::string    Pop3User   = "vasya.pupkin@gmail.com";
	const std::string    Pop3Pass   = "password";

	UseWinSock ws(2, 2);
	if( !ws )
		return -1;

	u_long srvr_bin_addr = GetBinAddr(Pop3Server.c_str());
	if( INADDR_NONE==srvr_bin_addr ) {
		return -1;
	}

	sockaddr_in ssock_addr;
	ssock_addr.sin_family = AF_INET;
	ssock_addr.sin_port = htons(Pop3Port);
	ssock_addr.sin_addr.s_addr = srvr_bin_addr;

	SOCKET hServerSock = socket(AF_INET, SOCK_STREAM, 0);
	if( INVALID_SOCKET == hServerSock )
		return -1;
	AutoCloseSocket CloseSocket(hServerSock);

	int ws_ret = connect(hServerSock, (sockaddr *)&ssock_addr, sizeof(ssock_addr));
	if( SOCKET_ERROR != ws_ret ) {
		AutoShutdownConnection ShutdownConnection(hServerSock, SD_BOTH);
		std::cout<<"Connected to: "<<Pop3Server<<" port:"<<Pop3Port<<std::endl;

		try{
			LSockByteStream ss(hServerSock);
			LSSLContext SSLCtx;//in case we will need SSL
			LSSLByteStream ssls(&ss);//in case we will need SSL
			if( UseSSL ) {
				SSLCtx.AcquireCredentials();
				SSLCtx.Handshake(&ss, to_wstring(Pop3Server).c_str() );
				ssls.SetSSLContext(&SSLCtx);
			}

			//POP3 protocol conversation
			LPop3 pop3( UseSSL ? (LByteStream*)&ssls : (LByteStream*)&ss );
			pop3.Greeting();
			std::cout<<"Server greeting: "<<pop3.GetResponse();

			if( pop3.USER(Pop3User) && pop3.PASS(Pop3Pass) ) {
				std::cout<<"User name: "<<Pop3User<<std::endl;

				unsigned int MessagesCount;
				pop3.STAT(&MessagesCount);

				std::cout<<"Total messages: "<<MessagesCount<<std::endl<<std::endl;
				std::vector<char> msg_body;
				for( unsigned int i=1; i<MessagesCount+1; ++i) {
					pop3.TOP(i, 0, &msg_body);
					msg_body.push_back('\0');
					std::cout<<"Message #"<<i<<" headers:"<<std::endl;
					std::cout<<&msg_body[0];
				}
			}

			pop3.QUIT();
		}
		catch(LPop3::BAD_POP3_PROTOCOL&){//some problem with POP3
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

