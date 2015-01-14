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

#if !defined(L_SMTP_H)
#define L_SMTP_H

#include <vector>
#include <string>

class LByteStream; //#include "ByteStream.h"

#ifdef _WIN32
#	define LSMTP_STARTTTLS 1
	class LSSLByteStream; //#include "SSLByteStream.h"
#endif

struct SMTP_REPLY_CODE
{
	SMTP_REPLY_CODE(const char* reply)
		:first_digit(reply[0]), second_digit(reply[1]), third_digit(reply[2]){}

	char first_digit;
	char second_digit;
	char third_digit;

	operator bool() const {return '2'==first_digit||'3'==first_digit;}
	inline bool operator ==(const char* c) const {return c[0]==first_digit&&c[1]==second_digit&&c[2]==third_digit;}
	inline bool operator !=(const char* c) const {return c[0]!=first_digit||c[1]!=second_digit||c[2]!=third_digit;}
};

class LSmtp
{
	enum{MAX_REPLY_SIZE=512, NET_BUFFER_LENGTH=4*1024};//RFC 1939: Responses may be up to 512 characters long, including the terminating CRLF.
public:
	//thows if something wrong with SMTP conversation
	struct BAD_SMTP_PROTOCOL{};

public:
	LSmtp(LByteStream* SBS);
	~LSmtp();
	SMTP_REPLY_CODE Greeting();
	SMTP_REPLY_CODE NOOP();
	SMTP_REPLY_CODE HELO(const std::string& domain);
	SMTP_REPLY_CODE EHLO(const std::string& domain, std::vector<std::string>* Extensions);

#ifdef LSMTP_STARTTTLS
	//при успешном завершении STARTTLS, весь последующий обмен данными будет осуществляться через SSL/TLS.
	//при этом первичная инициализаци SSL канала(Handshake) лежит на вызывающем,
	//и должна осуществляться _после_ успешного выполнения STARTTLS,
	//но _до_ выполнения любой другой команды.
	SMTP_REPLY_CODE STARTTLS(LSSLByteStream* SSLBS);
#endif

	SMTP_REPLY_CODE AUTH_PLAIN(const std::string& authid, const std::string& userid, const std::string& passwd);
	SMTP_REPLY_CODE MAIL(const std::string& reverse_path);
	SMTP_REPLY_CODE RCPT(const std::string& forward_path);
	SMTP_REPLY_CODE DATA(const char* msg, size_t size);//size must not include terminating '\0'
	/*
	SMTP_REPLY_CODE DATA(const std::vector<char>& msg)
		{return DATA(&msg[0], msg.size());}
	SMTP_REPLY_CODE DATA(const std::vector<unsigned char>& msg)
		{return DATA(reinterpret_cast<const char*>(&msg[0]), msg.size());}*/
	SMTP_REPLY_CODE RSET();
	SMTP_REPLY_CODE QUIT();

	std::string GetReply() const {return std::string(m_Reply);}

private:
	//считывание только первой строки ответа, даже если их несколько
	SMTP_REPLY_CODE ReadStatusLine(unsigned int* StatusLineLen, unsigned int* ReadedDataLen);
	//считывание всего ответа, даже если он многострочный
	//при этом первая строка помещается в m_Reply, а все остальные в lines (но с обрезанным кодом)
	SMTP_REPLY_CODE ReadReply(std::vector<std::string>* lines=0);

private:
	LByteStream* m_BS;
	int m_ReplyCode;
	char m_Reply[MAX_REPLY_SIZE+1];
};

#endif //L_SMTP_H
