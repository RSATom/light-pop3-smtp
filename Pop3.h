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

#if !defined(L_POP3_H)
#define L_POP3_H

#include <vector>
#include <string>

#include "ByteStream.h"

//POP3 command members returns true if +OK and false if -ERR.
//Can thow BAD_POP3_PROTOCOL() as exception,
//or can rethrow exceptions from LByteStream.
class LPop3
{
	//RFC 1939: Responses may be up to 512 characters long, including the terminating CRLF.
	enum{MAX_RESPONSE_SIZE=512, NET_BUFFER_LENGTH=4*1024};

public:
	//thows if something wrong with POP3 conversation
	struct BAD_POP3_PROTOCOL{};

public:
	LPop3(LByteStream* BS);
	~LPop3(){}
	void Greeting();
	void NOOP();
	bool USER(const std::string& user);
	bool PASS(const std::string& pass);
	void STAT(unsigned int* Count);
	//returns list of messages size, but sometimes numbers are inaccurate
	bool LIST(std::vector<unsigned int>*);
	bool UIDL(std::vector<std::string>*);
	//numbering from 1
	bool RETR(unsigned int msg_numb, std::vector<char>* out_msg);
	bool TOP(unsigned int msg_numb, unsigned int lines, std::vector<char>* out_msg);
	bool DELE(unsigned int msg_numb);
	void RSET();
	void QUIT();

	std::string GetResponse() const {return std::string(m_Response);}

private:
	//true if +OK, false if -ERR
	bool ReadStatusLine(unsigned int* StatusLineLen=0, unsigned int* ReadedDataLen=0);
	bool ReadLISTResponse(std::vector<unsigned int>*);
	bool ReadUIDLResponse(std::vector<std::string>*);
	bool ReadRETRResponse(std::vector<char>* out_msg);

private:
	LByteStream* m_BS;
	char m_Response[MAX_RESPONSE_SIZE+1];
};

#endif //L_POP3_H
