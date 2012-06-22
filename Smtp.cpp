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
#ifdef _WIN32
//disable min/max macro from <windows.h>
#	define NOMINMAX 1
#endif

#include "Smtp.h"
#include "Base64Codec.h"

#include "ByteStream.h"

#ifdef _WIN32
#	include "SSLByteStream.h"
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

inline int FindFirstCRLF(const char* buf, int start_offset, int data_len)
{
	for(int i=std::max(start_offset, 1); i<data_len; ++i){
		if('\r'==buf[i-1]&&'\n'==buf[i]){
			return i+1;
		}
	}
	return 0;
}


LSmtp::LSmtp(LByteStream* SBS)
	:m_BS(SBS)
{

}

LSmtp::~LSmtp()
{

}

//считывание только первой строки ответа, даже если их несколько
SMTP_REPLY_CODE LSmtp::ReadStatusLine(unsigned int* StatusLineLen, unsigned int* ReadedDataLen)
{
	unsigned int BuffOffset=0;
	unsigned int SecondLineOffset=0;
	do{
		unsigned int ret = m_BS->RawRecv(m_Reply+BuffOffset, MAX_REPLY_SIZE-BuffOffset);
		BuffOffset+=ret;

		//попробуйем выделить заголовочную часть ответа
		SecondLineOffset = FindFirstCRLF(m_Reply, BuffOffset-ret, BuffOffset);
	}while(BuffOffset<MAX_REPLY_SIZE&&0==SecondLineOffset);

	//нужно расшифровать ответ
	if(0==SecondLineOffset||//завершающий первую строку CRLF так и не был найден
	   SecondLineOffset<6||//6 = 3 цифры + разделитель + CRLF
	   ('-'!=m_Reply[3]&&' '!=m_Reply[3])){//неправильный разделитель
		throw BAD_SMTP_PROTOCOL();
	}

	//выставим завершающий 0
	m_Reply[BuffOffset]='\0';

	if(StatusLineLen) *StatusLineLen = SecondLineOffset;
	if(ReadedDataLen) *ReadedDataLen = BuffOffset;

	return m_Reply;
}

//любой Reply в SMTP может быть multiline
SMTP_REPLY_CODE LSmtp::ReadReply(std::vector<std::string>* lines)
{
	unsigned int LineStartOffset=0;
	unsigned int NextLineOffset=0;
	unsigned int ReadedDataLen=0;
	SMTP_REPLY_CODE RC = ReadStatusLine(&NextLineOffset, &ReadedDataLen);
	if('-'==m_Reply[3]){//не последняя строка
		char Reply[MAX_REPLY_SIZE+1];
		memcpy(&Reply[0], &m_Reply[NextLineOffset], ReadedDataLen-NextLineOffset);
		ReadedDataLen-=NextLineOffset;
		m_Reply[NextLineOffset]='\0';
		NextLineOffset=0;

		do{
			if(0!=NextLineOffset){
				LineStartOffset=NextLineOffset;
				NextLineOffset=0;
			}

			//попробуйем найти начало следующей строки
			NextLineOffset = FindFirstCRLF(Reply, LineStartOffset, ReadedDataLen);

			if(0==NextLineOffset){
				//следующую строку не нашли
				if(ReadedDataLen-LineStartOffset>=MAX_REPLY_SIZE){
					//при этом размер полученной строки уже достиг максимального размера - значит кривой протокол
					throw BAD_SMTP_PROTOCOL();
				}

				//переносим хвост в начало, для того чтобы освободить место для новой порции данных с сервера
				memmove(&Reply[0], &Reply[LineStartOffset], ReadedDataLen-LineStartOffset);
				ReadedDataLen-=LineStartOffset;
				LineStartOffset=0;
				NextLineOffset=0;
				//получаем новую порцию данных
				ReadedDataLen+=m_BS->RawRecv(Reply+ReadedDataLen, MAX_REPLY_SIZE-ReadedDataLen);
			}
			else{
				if(NextLineOffset-LineStartOffset<6|| //6 = 3 цифры + разделитель + CRLF
					('-'!=Reply[LineStartOffset+3]&&' '!=Reply[LineStartOffset+3])){//неправильный разделитель
					throw BAD_SMTP_PROTOCOL();
				}

				if(lines) lines->push_back(std::string(&Reply[LineStartOffset+4], NextLineOffset-LineStartOffset-4-2));//4 = 3 символа кода результата + 1 разделитель+2 CRLF
			}

		}while(0==NextLineOffset||' '!=Reply[LineStartOffset+3]);//выход если найдено окончание строки и строка последняя


	}
	return RC;
}

SMTP_REPLY_CODE LSmtp::Greeting()
{
	return ReadReply();
}

SMTP_REPLY_CODE LSmtp::NOOP()
{
	//NOOP <CRLF>

	const char cmdNOOP[]="NOOP\r\n";

	m_BS->RawSend(cmdNOOP, sizeof(cmdNOOP)-1);//учитываем завершающий '\0';

	return ReadReply();
}

SMTP_REPLY_CODE LSmtp::HELO(const std::string& domain)//RFC0821: The maximum total length of a domain name or number is 64 characters
{
	//ASSERT(domain.size()<=64);
	char cmdHELO[sizeof("HELO ")-1+64+sizeof("\r\n")-1 + 1];//должно хватить
	size_t size = sprintf(cmdHELO, "HELO %.64s\r\n", domain.c_str());
	//ASSERT(size<sizeof(cmdHELO));

	m_BS->RawSend(cmdHELO, size);

	return ReadReply();
}

SMTP_REPLY_CODE LSmtp::EHLO(const std::string& domain, std::vector<std::string>* Extensions)
{
	//ASSERT(domain.size()<=64);
	char cmdEHLO[sizeof("EHLO ")-1+64+sizeof("\r\n")-1 + 1];//должно хватить
	size_t size = sprintf(cmdEHLO, "EHLO %.64s\r\n", domain.c_str());
	//ASSERT(size<sizeof(cmdEHLO));

	m_BS->RawSend(cmdEHLO, size);

	return ReadReply(Extensions);
}

#ifdef LSMTP_STARTTTLS
SMTP_REPLY_CODE LSmtp::STARTTLS(LSSLByteStream* SSLBS)
{
	//STARTTLS<CRLF>

	const char cmdSTARTTLS[]="STARTTLS\r\n";

	m_BS->RawSend(cmdSTARTTLS, sizeof(cmdSTARTTLS)-1);//учитываем завершающий '\0';

	SMTP_REPLY_CODE R = ReadReply();
	if(R){//подменяем стрим только в случае успешного выполнения команды
		m_BS = SSLBS;
	}
	return R;
}
#endif

SMTP_REPLY_CODE LSmtp::AUTH_PLAIN(const std::string& authid, const std::string& userid, const std::string& passwd)
{
	char cmdAUTH_PLAIN[sizeof("AUTH PLAIN ")-1+((255+1+255+1+255+1)*4/3+4)+sizeof("\r\n")-1]="AUTH PLAIN ";//должно хватить на все
	size_t start_offset=sizeof("AUTH PLAIN ")-1;
	size_t offset = start_offset;
	if(!authid.empty()){
		memcpy(cmdAUTH_PLAIN+offset, &authid[0], authid.length());
		offset+=authid.length();
	}
	cmdAUTH_PLAIN[offset]='\0';
	++offset;
	if(!userid.empty()){
		memcpy(cmdAUTH_PLAIN+offset, &userid[0], userid.length());
		offset+=userid.length();
	}
	cmdAUTH_PLAIN[offset]='\0';
	++offset;
	if(!passwd.empty()){
		memcpy(cmdAUTH_PLAIN+offset, &passwd[0], passwd.length());
		offset+=passwd.length();
	}
	cmdAUTH_PLAIN[offset]='\0';
	++offset;
	offset=start_offset+Base64InplaceEnc(cmdAUTH_PLAIN+start_offset, offset-start_offset);
	cmdAUTH_PLAIN[offset]='\r';
	++offset;
	cmdAUTH_PLAIN[offset]='\n';
	++offset;

	m_BS->RawSend(cmdAUTH_PLAIN, offset);

	return ReadReply();
}

SMTP_REPLY_CODE LSmtp::QUIT()
{
	const char cmdQUIT[]="QUIT\r\n";

	m_BS->RawSend(cmdQUIT, sizeof(cmdQUIT)-1);//учитываем завершающий '\0';

	return ReadReply();
}

//RFC0821: The maximum total length of a reverse-path or forward-path is 256 characters (including the punctuation and element separators)
SMTP_REPLY_CODE LSmtp::MAIL(const std::string& reverse_path)
{
	//ASSERT(reverse_path.size()<=256);

	//MAIL <SP> FROM:<reverse-path> <CRLF>

	char cmdMAIL[sizeof("MAIL FROM:<")-1+256+sizeof(">\r\n")-1 + 1];//должно хватить
	size_t size = sprintf(cmdMAIL, "MAIL FROM:<%.256s>\r\n", reverse_path.c_str());
	//ASSERT(size<sizeof(cmdMAIL));

	m_BS->RawSend(cmdMAIL, size);

	return ReadReply();
}

//RFC0821: The maximum total length of a reverse-path or forward-path is 256 characters (including the punctuation and element separators)
SMTP_REPLY_CODE LSmtp::RCPT(const std::string& forward_path)
{
	//ASSERT(forward_path.size()<=256);

	//RCPT <SP> TO:<forward-path> <CRLF>

	char cmdRCPT[sizeof("RCPT TO:<")-1+256+sizeof(">\r\n")-1 + 1];//должно хватить
	size_t size = sprintf(cmdRCPT, "RCPT TO:<%.256s>\r\n", forward_path.c_str());
	//ASSERT(size<sizeof(cmdRCPT));

	m_BS->RawSend(cmdRCPT, size);

	return ReadReply();
}

SMTP_REPLY_CODE LSmtp::DATA(const char* msg, size_t sz)
{
	//int sz = msg.size();
	if(sz<5||!('\r'==msg[sz-5]&&'\n'==msg[sz-4]&&'.'==msg[sz-3]&&'\r'==msg[sz-2]&&'\n'==msg[sz-1])){
		//ASSERT(false);//неправильно оформленное письмо. должно оканчиваться "\r\n.\r\n"
		return "501";
	}

	const char cmdDATA[]="DATA\r\n";

	m_BS->RawSend(cmdDATA, sizeof(cmdDATA)-1);//учитываем завершающий '\0';

	SMTP_REPLY_CODE RC = ReadReply();
	if(RC=="354"){//If accepted, the receiver-SMTP returns a 354 Intermediate reply and considers all succeeding lines to be the message text.
		m_BS->RawSend(msg, sz);
		/*int sz = msg.size();
		const char cmdDOTCRLF[]="\r\n.\r\n";
		m_BS->RawSend(cmdDOTCRLF, sizeof(cmdDOTCRLF)-1);//учитываем завершающий '\0';
		*/
		return ReadReply();
	}
	return RC;
}

SMTP_REPLY_CODE LSmtp::RSET()
{
	//RSET <CRLF>

	const char cmdRSET[]="RSET\r\n";

	m_BS->RawSend(cmdRSET, sizeof(cmdRSET)-1);//учитываем завершающий '\0';

	return ReadReply();
}

