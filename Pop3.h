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
