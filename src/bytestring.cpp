/*************************************************************************
 *   Copyright (C) 2011-2012 by Paul-Louis Ageneau                       *
 *   paul-louis (at) ageneau (dot) org                                   *
 *                                                                       *
 *   This file is part of TeapotNet.                                     *
 *                                                                       *
 *   TeapotNet is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU Affero General Public License as      *
 *   published by the Free Software Foundation, either version 3 of      *
 *   the License, or (at your option) any later version.                 *
 *                                                                       *
 *   TeapotNet is distributed in the hope that it will be useful, but    *
 *   WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the        *
 *   GNU Affero General Public License for more details.                 *
 *                                                                       *
 *   You should have received a copy of the GNU Affero General Public    *
 *   License along with TeapotNet.                                       *
 *   If not, see <http://www.gnu.org/licenses/>.                         *
 *************************************************************************/

#include "bytestring.h"
#include "exception.h"

namespace tpot
{

ByteString::ByteString(void)
{

}

ByteString::ByteString(const char *data, size_t size) :
		std::deque<char>(data,data+size)
{

}

ByteString::~ByteString(void)
{

}

void ByteString::clear(void)
{
	std::deque<char>::clear();
}

void ByteString::append(char value, int n)
{
	for(int i=0; i<n; ++i)
		push_back(value);
}

void ByteString::append(const ByteString &bs)
{
	insert(end(), bs.begin(), bs.end());
}

void ByteString::append(const char *array, size_t size)
{
	insert(end(), array, array+size);
}

void ByteString::fill(char value, int n)
{
	assign(n, value);
}

void ByteString::serialize(Serializer &s) const
{
	s.output(uint32_t(size()));

	for(int i=0; i<size(); ++i)
		s.output(uint8_t(at(i)));	
}

bool ByteString::deserialize(Serializer &s)
{
	clear();

	uint32_t count;
	if(!s.input(count)) return false;

	uint8_t b;
	for(uint32_t i=0; i<count; ++i)
	{
		AssertIO(!s.input(b));
		push_back(b);
	}

	return true;
}

void ByteString::serialize(Stream &s) const
{
	String str;
	for(int i=0; i<size(); ++i)
	{
		std::ostringstream oss;
		oss.width(2);
		oss.fill('0');
		oss<<std::hex<<std::uppercase<<unsigned(uint8_t(at(i)));
		s<<oss.str();
	}
}

bool ByteString::deserialize(Stream &s)
{
	clear();
	
	String str;
	if(!s.read(str)) return false;
	
	int count = (str.size()+1)/2;
	for(int i=0; i<count; ++i)
	{
		std::string byte;
		byte+= str[i*2];
		if(i*2+1 != str.size()) byte+= str[i*2+1];
		else byte+= '0';
		std::istringstream iss(byte);

		unsigned value = 0;
		iss>>std::hex;
		if(!(iss>>value))
			throw InvalidData("Invalid hexadecimal representation");

		push_back(uint8_t(value % 256));
	}
	
	return true;
}

size_t ByteString::readData(char *buffer, size_t size)
{
	if(this->empty()) return 0;
	size = std::min(size, this->size());
	std::copy(begin(), begin()+size, buffer);
	erase(begin(), begin()+size);
	return size;
}

void ByteString::writeData(const char *data, size_t size)
{
	insert(end(), data, data+size);
}

}

