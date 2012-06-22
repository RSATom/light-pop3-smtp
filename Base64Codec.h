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
