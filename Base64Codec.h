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

#if !defined(L_BASE64_CODEC_h)
#define L_BASE64_CODEC_h

//blocks_in_line - количество блоков в строке минус один, т.е. 0 соответствует 1 блоку в строке.
//соответственно максимальная длинна строки=1024 (256*4)
inline unsigned int Base64EncLen(unsigned int L, unsigned char blocks_in_line=80/4-1)
{
	unsigned short line_size = (blocks_in_line+1)*4;

	unsigned int EncCharCount = (L/3+(L%3?1:0))*4;
	EncCharCount+=2*(EncCharCount/line_size+(EncCharCount%line_size?1:0)-1);
	return EncCharCount;
}

//blocks_in_line - количество блоков в строке минус один, т.е. 0 соответствует 1 блоку в строке.
//соответственно максимальная длинна строки=1024 (256*4).
//результат ориентировочный, т.к. теоретически закодированные данные могут содержать строки переменной длинны
inline unsigned int Base64DecLen(unsigned int L, unsigned char blocks_in_line=80/4-1)
{
	unsigned short line_size = (blocks_in_line+1)*4;
	L-=2*(L/line_size + (L%line_size?1:0)-1);
	unsigned int EncCharCount = (L/4+(L%4?1:0))*3;
	return EncCharCount;
}

//blocks_in_line - количество блоков в строке минус один, т.е. 0 соответствует 1 блоку в строке.
//соответственно максимальная длинна строки=1024 (256*4).
//out должен быть размера не меньшего чем Base64EncLen(in_len).
//кодированная строка никогда не заканчивается CRLF.
//возвращает размер кодированных данных.
unsigned int Base64Enc(const void* in, int in_len, char* out, unsigned char blocks_in_line=80/4-1);

//функция использующая один и тот же буфер и как источник и как получатель,
//как следствие, inout должен быть размера не меньшего чем Base64EncLen(in_len)
//blocks_in_line - количество блоков в строке минус один, т.е. 0 соответствует 1 блоку в строке.
//соответственно максимальная длинна строки=1024 (256*4)
//кодированная строка никогда не заканчивается CRLF
//возвращает размер кодированных данных
unsigned int Base64InplaceEnc(void* inout, int in_len, unsigned char blocks_in_line=80/4-1);

//возвращает 0 в случае некорректного формата, или размер декодированных данных
unsigned int Base64InplaceDec(char* inout, unsigned int in_len);


#endif //L_BASE64_CODEC_h
