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

#include "Pop3.h"

LPop3::LPop3(LByteStream* BS)
	:m_BS(BS)
{

}

unsigned int StrToInt(const char* buf, int data_len)
{
	unsigned int num=0;

	for(;data_len>0;++buf,--data_len){
		num=num*10;
		switch(buf[0]){
			case '9':num+=9;break;
			case '8':num+=8;break;
			case '7':num+=7;break;
			case '6':num+=6;break;
			case '5':num+=5;break;
			case '4':num+=4;break;
			case '3':num+=3;break;
			case '2':num+=2;break;
			case '1':num+=1;break;
			case '0':break;
			default:
				throw LPop3::BAD_POP3_PROTOCOL();//only numbers expecting
		}
	}

	return num;
}

/*
inline bool CheckEndCRLF(const char* buf, int data_len)
{
	return data_len>2&&'\r'==buf[data_len-1]&&'\n'==buf[data_len];
}
*/

inline bool IsOKResponse(const char* buf, int data_len)
{
	//ASSERT(data_len>0);
	return ('+'==buf[0]);
}

inline int FindFirstCRLF(const char* buf, int start_offset, int data_len)
{
	for(int i = std::max(start_offset, 1); i<data_len; ++i){
		if('\r'==buf[i-1]&&'\n'==buf[i]){
			return i+1;
		}
	}
	return 0;
}

bool LPop3::ReadStatusLine(unsigned int* StatusLineLen, unsigned int* ReadedDataLen)
{
	unsigned int BuffOffset=0;
	unsigned int SecondLineOffset=0;
	do{
		unsigned int ret = m_BS->RawRecv(m_Response+BuffOffset, MAX_RESPONSE_SIZE-BuffOffset);
		BuffOffset+=ret;
	
		//попробуйем выделить заголовочную часть ответа
		SecondLineOffset = FindFirstCRLF(m_Response, BuffOffset-ret, BuffOffset);
	}while(BuffOffset<MAX_RESPONSE_SIZE&&0==SecondLineOffset);

	//нужно расшифровать ответ
	if(0==SecondLineOffset){//завершающий первую строку CRLF так и не был найден
		throw BAD_POP3_PROTOCOL();
	}

	//выставим завершающий 0
	m_Response[BuffOffset]='\0';

	if(StatusLineLen) *StatusLineLen = SecondLineOffset;
	if(ReadedDataLen) *ReadedDataLen = BuffOffset;
	return IsOKResponse(m_Response, SecondLineOffset);
}

bool LPop3::ReadLISTResponse(std::vector<unsigned int>* l)
{
	//ASSERT(l);
	unsigned int BuffOffset=0;
	unsigned int SecondLineOffset=0;
	//проверим на ошибку полученный ответ
	if(!ReadStatusLine(&SecondLineOffset, &BuffOffset)){
		//ASSERT(BuffOffset==SecondLineOffset);//в этом случае может быть только одна строчка данных
		return false;
	}

	//значит всетаки несколько строк
	//ASSERT(l->empty());

	char NetBuf[NET_BUFFER_LENGTH];
	memcpy(&NetBuf[0], &m_Response[SecondLineOffset], BuffOffset-SecondLineOffset);
	int net_buf_data_len=BuffOffset-SecondLineOffset;
	m_Response[SecondLineOffset]='\0';

	//цикл разбора списка, с получением дополнительных блоков в случае необходимости
	int start=0;
	while(true){
		//S: +OK 2 messages (320 octets)
		//S: 1 120
		//S: 2 200
		//S: .
		int NextLineOffset = FindFirstCRLF(NetBuf, start, net_buf_data_len);
		if(0==NextLineOffset){//блок кончился а строка нет, надо считывать следующий блок (с сохранением необработанных данных естественно)
			//сначала перенесем хвост в начало
			memmove(&NetBuf[0], &NetBuf[start], net_buf_data_len-start);
			net_buf_data_len-=start;
			start=0;
		
			//затем считаем новую порцию из сокета
			unsigned int ret = m_BS->RawRecv(&NetBuf[net_buf_data_len], NET_BUFFER_LENGTH-net_buf_data_len);
			net_buf_data_len+=ret;
		}
		else{
			//ASSERT(NextLineOffset-start>=3);//при любом раскладе строка не может быть меньше 3-х символов
			if('.'==NetBuf[start]){//конец списка?
				//ASSERT(NextLineOffset-start==3);//в этом случае размер должен быть равен точно трем.
				return true;//основной выход из цикла
			}
			else{//нет, не конец
				//пропустим номер сообщения
				for(;NetBuf[start]!=' ';++start);
				++start;//перескочим пробел
				//ASSERT((NextLineOffset-2)-start>1);//"-2"-это CRLF. хоть один символ должен быть.
				l->push_back(StrToInt(&NetBuf[start], (NextLineOffset-2)-start));
				start=NextLineOffset;
			}
		}
	}
	return false;
}

bool LPop3::ReadUIDLResponse(std::vector<std::string>* l)
{
	//ASSERT(l);
	unsigned int BuffOffset=0;
	unsigned int SecondLineOffset=0;
	//проверим на ошибку полученный ответ
	if(!ReadStatusLine(&SecondLineOffset, &BuffOffset)){
		//ASSERT(BuffOffset==SecondLineOffset);//в этом случае может быть только одна строчка данных
		return false;
	}

	//значит всетаки несколько строк
	//ASSERT(l->empty());
	char NetBuf[NET_BUFFER_LENGTH];
	memcpy(&NetBuf[0], &m_Response[SecondLineOffset], BuffOffset-SecondLineOffset);
	int net_buf_data_len=BuffOffset-SecondLineOffset;
	m_Response[SecondLineOffset]='\0';

	//цикл разбора списка, с получением дополнительных блоков в случае необходимости
	int start=0;

	while(true){
          //S: +OK
          //S: 1 whqtswO00WBw418f9t5JxYwZ
          //S: 2 QhdPYR:00WBw1Ph7x7
          //S: .
		int NextLineOffset = FindFirstCRLF(NetBuf, start, net_buf_data_len);
		if(0==NextLineOffset){//блок кончился а строка нет, надо считывать следующий блок (с сохранением необработанных данных естественно)
			//сначала перенесем хвост в начало
			memmove(&NetBuf[0], &NetBuf[start], net_buf_data_len-start);
			net_buf_data_len-=start;
			start=0;
		
			//затем считаем новую порцию из сокета
			unsigned int ret = m_BS->RawRecv(&NetBuf[net_buf_data_len], NET_BUFFER_LENGTH-net_buf_data_len);
			net_buf_data_len+=ret;
		}
		else{
			//ASSERT(NextLineOffset-start>=3);//при любом раскладе строка не может быть меньше 3-х символов
			if('.'==NetBuf[start]){//конец списка?
				//ASSERT(NextLineOffset-start==3);//в этом случае размер должен быть равен точно трем.
				return true;//основной выход из цикла
			}
			else{//нет, не конец
				//пропустим номер сообщения
				for(;NetBuf[start]!=' ';++start);
				++start;//перескочим пробел
				//ASSERT((NextLineOffset-2)-start>1);//"-2"-это CRLF. хоть один символ должен быть.
				l->push_back(std::string(&NetBuf[start], (NextLineOffset-2)-start));
				start=NextLineOffset;
			}
		}
	}
	return false;
}

bool LPop3::ReadRETRResponse(std::vector<char>* out_msg)
{
	//ASSERT(out_msg);
	unsigned int BuffOffset=0;
	unsigned int SecondLineOffset=0;
	//проверим на ошибку полученный ответ
	if(!ReadStatusLine(&SecondLineOffset, &BuffOffset)){
		//ASSERT(BuffOffset==SecondLineOffset);//в этом случае может быть только одна строчка данных
		return false;
	}

	//значит всетаки несколько строк
	out_msg->clear();//ASSERT(out_msg->empty());

	char NetBuf[NET_BUFFER_LENGTH];
	memcpy(&NetBuf[0], &m_Response[SecondLineOffset], BuffOffset-SecondLineOffset);
	int net_buf_data_len=BuffOffset-SecondLineOffset;
	m_Response[SecondLineOffset]='\0';

	//цикл разбора списка, с получением дополнительных блоков в случае необходимости
	int start=0;
	while(true){
		int NextLineOffset = FindFirstCRLF(NetBuf, start, net_buf_data_len);
		if(0==NextLineOffset){//блок кончился а строка нет, надо считывать следующий блок (с сохранением необработанных данных естественно)
			//запишем предыдущий кусок письма
			out_msg->insert(out_msg->end(), NetBuf, NetBuf+start);
			//сначала перенесем хвост в начало
			memmove(&NetBuf[0], &NetBuf[start], net_buf_data_len-start);
			net_buf_data_len-=start;
			start=0;
		
			//затем считаем новую порцию из сокета
			unsigned int ret = m_BS->RawRecv(&NetBuf[net_buf_data_len], NET_BUFFER_LENGTH-net_buf_data_len);
			net_buf_data_len+=ret;
		}
		else{
			//ASSERT(NextLineOffset-start>=2);//при любом раскладе строка не может быть меньше 2-х символов
			if(NextLineOffset-start==3&&'.'==NetBuf[start]&&'\r'==NetBuf[start+1]&&'\n'==NetBuf[start+2]){//конец списка?
				//запишем последний кусок письма
				out_msg->insert(out_msg->end(), NetBuf, NetBuf+start);
				//ASSERT(NextLineOffset==net_buf_data_len);
				return true;//основной выход из цикла
			}
			//нет, не конец
			start=NextLineOffset;
		}
	}
	return false;
}


void LPop3::Greeting()
{
	/*VERIFY(*/ReadStatusLine()/*)*/;//RFC 1939: Once the TCP connection has been opened by a POP3 client, the POP3 server issues a one line greeting. This can be any positive response.
}

void LPop3::NOOP()
{
	const char cmdNOOP[]="NOOP\r\n";

	m_BS->RawSend(cmdNOOP, sizeof(cmdNOOP)-1);//учитываем завершающий '\0';

	/*VERIFY(*/ReadStatusLine()/*)*/;//RFC 1939: Possible Responses: +OK
}

bool LPop3::USER(const std::string& user)
{
	std::string cmdUSER = "USER "+user+"\r\n";

	m_BS->RawSend(&cmdUSER[0], cmdUSER.length());

	return ReadStatusLine();
}

bool LPop3::PASS(const std::string& pass)
{
	std::string cmdPASS = "PASS "+pass+"\r\n";

	m_BS->RawSend(&cmdPASS[0], cmdPASS.length());

	return ReadStatusLine();
}

void LPop3::STAT(unsigned int* Count)
{
	const char cmdSTAT[]="STAT\r\n";
	m_BS->RawSend(cmdSTAT, sizeof(cmdSTAT)-1);//учитываем завершающий '\0';

	*Count=0;
	if(ReadStatusLine()){
		//Possible Responses:
		//+OK nn mm
		int start=0;
		int end=0;
		for(;m_Response[start]!=' ';++start);
		++start;
		end=start;
		for(;m_Response[end]!=' ';++end);
		*Count=StrToInt(&m_Response[start], end-start);
	}
	//else ASSERT(false);//RFC 1939: Possible Responses: +OK
}


bool LPop3::LIST(std::vector<unsigned int>* l)
{
	const char cmdLIST[]="LIST\r\n";
	m_BS->RawSend(cmdLIST, sizeof(cmdLIST)-1);//учитываем завершающий '\0';

	return ReadLISTResponse(l);
}

bool LPop3::UIDL(std::vector<std::string>* l)
{
	const char cmdLIST[]="UIDL\r\n";
	m_BS->RawSend(cmdLIST, sizeof(cmdLIST)-1);//учитываем завершающий '\0';

	return ReadUIDLResponse(l);
}


bool LPop3::RETR(unsigned int msg_numb, std::vector<char>* out_msg)
{
	//ASSERT(msg_numb>0);
	char cmdRETR[30];//должно хватить с приличным запасом
	size_t size = sprintf(cmdRETR, "RETR %d\r\n", msg_numb);
	//ASSERT(size<sizeof(cmdRETR));

	m_BS->RawSend(cmdRETR, size);

	return ReadRETRResponse(out_msg);
}

bool LPop3::TOP(unsigned int msg_numb, unsigned int lines, std::vector<char>* out_msg)
{
	//ASSERT(msg_numb>0);
	char cmdTOP[30];//должно хватить с приличным запасом
	size_t size = sprintf(cmdTOP, "TOP %d %d\r\n", msg_numb, lines);
	//ASSERT(size<sizeof(cmdTOP));

	m_BS->RawSend(cmdTOP, size);

	return ReadRETRResponse(out_msg);
}

bool LPop3::DELE(unsigned int msg_numb)
{
	//ASSERT(msg_numb>0);
	char cmdDELE[30];//должно хватить с приличным запасом
	size_t size = sprintf(cmdDELE, "DELE %d\r\n", msg_numb);
	//ASSERT(size<sizeof(cmdDELE));

	m_BS->RawSend(cmdDELE, size);

	return ReadStatusLine();
}

void LPop3::RSET()
{
	const char cmdRSET[]="RSET\r\n";

	m_BS->RawSend(cmdRSET, sizeof(cmdRSET)-1);//учитываем завершающий '\0';

	/*VERIFY(*/ReadStatusLine()/*)*/;//RFC 1939: Possible Responses: +OK
}

void LPop3::QUIT()
{
	const char cmdQUIT[]="QUIT\r\n";

	m_BS->RawSend(cmdQUIT, sizeof(cmdQUIT)-1);//учитываем завершающий '\0';

	/*VERIFY(*/ReadStatusLine()/*)*/;//RFC 1939: Possible Responses: +OK
}


