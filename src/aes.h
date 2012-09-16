/*************************************************************************
 *   Copyright (C) 2011-2012 by Paul-Louis Ageneau                       *
 *   paul-louis (at) ageneau (dot) org                                   *
 *                                                                       *
 *   This file is part of Arcanet.                                       *
 *                                                                       *
 *   Arcanet is free software: you can redistribute it and/or modify     *
 *   it under the terms of the GNU Affero General Public License as      *
 *   published by the Free Software Foundation, either version 3 of      *
 *   the License, or (at your option) any later version.                 *
 *                                                                       *
 *   Arcanet is distributed in the hope that it will be useful, but      *
 *   WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the        *
 *   GNU Affero General Public License for more details.                 *
 *                                                                       *
 *   You should have received a copy of the GNU Affero General Public    *
 *   License along with Arcanet.                                         *
 *   If not, see <http://www.gnu.org/licenses/>.                         *
 *************************************************************************/

#ifndef ARC_AES_H
#define ARC_AES_H

#include "include.h"
#include "stream.h"
#include "bytestream.h"
#include "bytestring.h"

namespace arc
{

#define AES_BLOCK_SIZE 16
#define AES_MAXNR 14

class Aes : public Stream, public ByteString
{
public:
  	Aes(ByteStream *bs);
	~Aes(void);
	
	void setEncryptionKey(const char *key, size_t size);
	void setDecryptionKey(const char *key, size_t size);
	
	void setEncryptionInit(const char *iv);
	void setDecryptionInit(const char *iv);
	
	size_t readData(char *buffer, size_t size);
	void writeData(const char *data, size_t size);

private:
  	struct Key
	{
	    uint32_t rd_key[4 *(AES_MAXNR + 1)];
	    int rounds;
	};
  
  	void setEncryptionKey(const char *key, size_t size, Key &out);
	void setDecryptionKey(const char *key, size_t size, Key &out);
  
  	void encrypt(char *in, char *out);
	void decrypt(char *in, char *out);
  
	size_t readBlock(char *out);
	

	ByteStream *mByteStream;
	
	Key mEncryptionKey;
	Key mDecryptionKey;
	char mEncryptionInit[AES_BLOCK_SIZE];
	char mDecryptionInit[AES_BLOCK_SIZE];
	
	char	mTempBlockIn[AES_BLOCK_SIZE];
	size_t	mTempBlockInSize;
	char	mTempBlockOut[AES_BLOCK_SIZE];
	size_t	mTempBlockOutSize;
};

}

#endif
