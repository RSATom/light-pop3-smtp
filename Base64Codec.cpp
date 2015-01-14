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

#include "Base64Codec.h"

const char Base64Alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char Base64DecAlphabet[]="n   odefghijklm       0123456789:;<=>?@ABCDEFGHI      JKLMNOPQRSTUVWXYZ[\\]^_`abc";
enum{
	Base64DecSkipChar=' ',
	Base64DecTableOffset='+',
	Base64DecAlphabetMinChar='0'
};

////////////////////////////////////////////////////////////////////////////////////
//кодирование
////////////////////////////////////////////////////////////////////////////////////
inline void Base64BlockEnc(const char* in/*[3]*/, char* out/*[4]*/, char block_len)
{
	if(block_len<3){
		out[3]='=';
		out[2]=(block_len>1)?(Base64Alphabet[(in[1]&0x0F)<<2]):'=';
		out[1]=Base64Alphabet[(in[0]&0x03)<<4|((block_len>1)?(in[1]&0xF0)>>4:0)];
	}
	else{
		out[3]=Base64Alphabet[in[2]&0x3F];
		out[2]=Base64Alphabet[(in[1]&0x0F)<<2|(in[2]&0xC0)>>6];
		out[1]=Base64Alphabet[(in[0]&0x03)<<4|(in[1]&0xF0)>>4];
	}
	out[0]=Base64Alphabet[(in[0]&0xFC)>>2];
}

//blocks_in_line - количество блоков в строке минус один, т.е. 0 соответствует 1 блоку в строке.
//соответственно максимальная длинна строки=1024 (256*4)
unsigned int Base64Enc(const void* _in, int len, char* out, unsigned char blocks_in_line/*=80/4-1*/)
{
	char const * const out_start = out;
	const char* in = static_cast<const char*>(_in);

	unsigned short line_size = (blocks_in_line+1)*4;

	while(len>0){
		for(char line_len=0; len>0&&line_len<line_size; len-=3, line_len+=4){
			Base64BlockEnc(in, out, len>3?3:len);
			in+=3; out+=4;
		}
		if(len>0){
			*out='\r';++out;
			*out='\n';++out;
		}
	}
	return out - out_start;
}

//blocks_in_line - количество блоков в строке минус один, т.е. 0 соответствует 1 блоку в строке.
//соответственно максимальная длинна строки=1024 (256*4)
unsigned int Base64InplaceEnc(void* io, int in_len, unsigned char blocks_in_line/*=80/4-1*/)
{
	char* inout = static_cast<char*>(io);

	unsigned short line_size = (blocks_in_line+1)*4;
	unsigned int enc_char_count = (in_len/3+(in_len%3?1:0))*4;
	unsigned int line_count = (enc_char_count/line_size+(enc_char_count%line_size?1:0));
	enc_char_count+=2*(line_count-1);
	unsigned enc_data_len = enc_char_count;

	if(in_len%3){
		char block_len = in_len%3;
		in_len-=block_len;
		enc_char_count-=4;
		Base64BlockEnc(&inout[in_len], &inout[enc_char_count], block_len);
	}

	for(unsigned int line_len=enc_char_count%(line_size+2); line_count>0; --line_count, line_len=line_size){
		for(; line_len>0; line_len-=4){
			in_len-=3;
			enc_char_count-=4;
			Base64BlockEnc(&inout[in_len], &inout[enc_char_count], 3);
		}
	
		if(1<line_count){
			inout[--enc_char_count]='\n';
			inout[--enc_char_count]='\r';
		}
	}

	return enc_data_len;
}

////////////////////////////////////////////////////////////////////////////////////
//декодирование
////////////////////////////////////////////////////////////////////////////////////
//служебная функция создания алфавита для декодирования
//с ее помощью был создан Base64DecAlphabet
short PrepBase64DecAlphabet(char* EncAlphabet, char EncAlphabetLen, char* dec_alph,
                            char SkipChar=Base64DecSkipChar, char MinChar=Base64DecAlphabetMinChar)
{
	unsigned char min_c='\xff';
	unsigned char max_c=0;
	for(unsigned char i=0; i<EncAlphabetLen; ++i ){
		if(EncAlphabet[i]<min_c) min_c = EncAlphabet[i];
		if(EncAlphabet[i]>max_c) max_c = EncAlphabet[i];
	}

	for(char c=min_c; c<=max_c; ++c){
		dec_alph[c-min_c]=SkipChar;
		for(char ao=0; ao<EncAlphabetLen; ++ao) if(EncAlphabet[ao]==c) dec_alph[c-min_c]=ao+MinChar;
	}

	return max_c<<8|min_c;
}

//сжимает в 3 байта предварительно декодированный блок
//размер блока не может быть меньше 2
inline void Base64BlockPack(const char* in/*[4]*/, char* out/*[3]*/, char block_len)
{
	out[0]=in[0]<<2|in[1]>>4;
	if(block_len<4){
		out[1]=(block_len>2)?(in[1]<<4|in[2]>>2):0;
		out[2]=0;
	}
	else{
		out[1]=in[1]<<4|in[2]>>2;
		out[2]=in[2]<<6|in[3];
	}
}

//возвращает 0 в случае некорректного формата, или размер декодированных данных
unsigned int Base64InplaceDec(char* inout, unsigned int in_len)
{
	unsigned int in_offset=0;
	unsigned int out_offset=0;

	while(in_offset<in_len){
		switch(inout[in_offset]){
			case '\r':
			case '\n': ++in_offset; break;
			default:{
				char block_offset=0;
				for(; block_offset<4&&(in_offset+block_offset)<in_len; ){
					unsigned char c=inout[in_offset+block_offset];
					if(c>=Base64DecTableOffset&&c<(Base64DecTableOffset+sizeof(Base64DecAlphabet)-1)&&
					   (c=Base64DecAlphabet[c-Base64DecTableOffset])!=Base64DecSkipChar){
						inout[in_offset+block_offset]=(c-Base64DecAlphabetMinChar);
						++block_offset;
					}
					else{
						//проверка на финальный '==' и '='
						if(((block_offset==1||block_offset==2)&&'='==inout[in_offset+block_offset]&&(in_offset+block_offset+1)<in_len&&'='==inout[in_offset+block_offset+1])||
						   (block_offset==3&&'='==inout[in_offset+block_offset])){
							in_len=in_offset+block_offset;
						}
						else
							return 0;
					}
				}
				if(block_offset<1)
					return 0;
			
				Base64BlockPack(&inout[in_offset], &inout[out_offset], block_offset);
			
				out_offset+=(block_offset-1);
				in_offset+=4;

				break;
			}
		}
	}
	return out_offset;
}
