/*************************************************************************
 *   Copyright (C) 2011-2018 by Paul-Louis Ageneau                       *
 *   paul-louis (at) ageneau (dot) org                                   *
 *                                                                       *
 *   This file is part of Plateform.                                     *
 *                                                                       *
 *   Plateform is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU Affero General Public License as      *
 *   published by the Free Software Foundation, either version 3 of      *
 *   the License, or (at your option) any later version.                 *
 *                                                                       *
 *   Plateform is distributed in the hope that it will be useful, but    *
 *   WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the        *
 *   GNU Affero General Public License for more details.                 *
 *                                                                       *
 *   You should have received a copy of the GNU Affero General Public    *
 *   License along with Plateform.                                       *
 *   If not, see <http://www.gnu.org/licenses/>.                         *
 *************************************************************************/

#include "pla/websocket.hpp"
#include "pla/crypto.hpp"	// for SHA1

namespace pla
{

// http://tools.ietf.org/html/rfc6455#section-5.2  Base Framing Protocol
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+

WebSocket *WebSocket::Upgrade(Http::Request &request, bool binary)
{
	String upgrade;
	if(request.headers.get("Upgrade", upgrade))
	{
		StringList protocols;
		upgrade.explode(protocols, ',');
		for(String &proto : protocols)
		{
			proto.trim();
			if(proto.toLower() == "websocket")
			{
				Http::Response response(request, 101);
				response.headers["Connection"] = "Upgrade";
				response.headers["Upgrade"] = "websocket";
				
				String key;
				if(request.headers.get("Sec-WebSocket-Key", key))
				{
					String guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
					String answerKey = Sha1().compute(key.trimmed() + guid).base64Encode();
					response.headers["Sec-WebSocket-Accept"] = answerKey;
				}
				
				response.send();
				
				request.stream = NULL;	// Steal the stream
				return new WebSocket(response.stream, binary, true);	// Masking may be disabled on server side
			}
		}
	}
	return NULL;
}

WebSocket::WebSocket(void) :
	mStream(NULL),
	mIsBinary(false)
{
	init();
}

WebSocket::WebSocket(Stream *stream, bool binary, bool disableMask) :
	WebSocket()
{
	Assert(stream);
	mStream = stream;
	mStream->setTimeout(duration(-1));
	mSendMask = !disableMask;
}

WebSocket::WebSocket(const String &url, bool binary) :
	WebSocket()
{
	connect(url, binary);
}

WebSocket::~WebSocket(void) 
{
	NOEXCEPTION(close());
}

void WebSocket::init(void) {
	mLength = 0;
	mLeft = 0;
	mFin = false;
	mMask = false;
	mSendMask = true;
	mSendContinuation = false;
}

void WebSocket::connect(const String &url, bool binary)
{
	close();
	mIsBinary = binary;
	mStream = Http::Connect(url);
	try {
		BinaryString key;
		Random().read(key, 16);
		
		Http::Request request(url, "GET");
		request.version = "1.1";
		request.headers["Connection"] = "Upgrade";
		request.headers["Upgrade"] = "websocket";
		request.headers["Sec-WebSocket-Version"] = "13";
		request.headers["Sec-WebSocket-Key"] = key.base64Encode();
		request.send(mStream);
		
		Http::Response response;
		response.recv(mStream);
		if(response.code != 101)
			throw Exception("Unexpected response code to WebSocket handshake request: " + String::number(response.code));
		if(response.headers["Upgrade"] != "websocket")
			throw Exception("WebSocket upgrade header mismatch");
		
		// We don't bother verifying Sec-WebSocket-Accept
		
		mStream->setTimeout(duration(-1));
		init();
	}
	catch(...)
	{
		delete mStream;
		mStream = NULL;
		throw;
	}
}

void WebSocket::close(void)
{
	if(mStream)
	{
		sendFrame(CLOSE, NULL, 0, false);
		delete mStream;
		mStream = NULL;
	}
}

size_t WebSocket::readData(char *buffer, size_t size)
{
	while(!mLeft)
	{
		if(mFin) return 0;
		if(!recvFrame()) return 0;
	}

	if(!mStream || size == 0) return 0;

	size = mStream->readData(buffer, std::min(size, size_t(mLeft)));
	if(mMask)
	{
		size_t offset = size_t((mLength - mLeft)%4);
		for(size_t i = 0; i < size; ++i)
			buffer[i]^= mMaskKey[(offset+i)%4];
	}
	mLeft-= size;
	return size;
}

void WebSocket::writeData(const char *data, size_t size)
{
	opcode_t opcode = mSendContinuation ? CONTINUATION : (mIsBinary ? BINARY_FRAME : TEXT_FRAME);
	sendFrameHeader(opcode, size, false);
	char buffer[BufferSize];
	uint64_t counter = 0;
	while(size_t(counter) < size)
	{
		size_t len = std::min(BufferSize, size - size_t(counter));
		std::copy(data+counter, data+counter+len, buffer);
		sendFrameData(buffer, len, &counter);
	}
}

bool WebSocket::waitData(duration timeout)
{
	return mLeft || mFin || mStream->waitData(timeout);
}

bool WebSocket::nextRead(void)
{
	if(!mStream) return false;
	discard();
	mFin = 0;
	return true;
}

bool WebSocket::nextWrite(void)
{
	sendFrame(CONTINUATION, NULL, 0, true);
	return true;
}

void WebSocket::setTimeout(duration timeout)
{
	mStream->setTimeout(timeout);
}

bool WebSocket::recvFrame(void)
{
	if(!mStream) return false;

	while(true)
	{
		Assert(mLeft == 0);

		uint8_t b1, b2;
		if(!mStream->readBinary(b1)) 
		{
			delete mStream;
			mStream = NULL;
			return false;
		}
		AssertIO(mStream->readBinary(b2));
		mFin = b1 & 0x80;
		mMask = b2 & 0x80;
		opcode_t opcode = opcode_t(b1 & 0x0F);
		mLength = b2 & 0x7F;

		if(mLength == 0x7E)
		{
			uint16_t extLen;
			AssertIO(mStream->readBinary(extLen));
			mLength = extLen;
		}
		else if(mLength == 0x7F)
		{
			uint64_t extLen;
			AssertIO(mStream->readBinary(extLen));
			mLength = extLen;
		}
		
		if(mMask) AssertIO(mStream->readBinary(mMaskKey, 4) == 4);
		mLeft = mLength;

		switch(opcode)
		{
			case TEXT_FRAME:
			case BINARY_FRAME:
			case CONTINUATION:
			{
				return true;
			}
			
			case PING:
			{
				sendFrameHeader(PONG, mLength, true);
				mFin = true;	// so readData returns 0 at end of frame data
				char buffer[BufferSize];
				size_t size;
				uint64_t counter = 0;
				while((size = mStream->readData(buffer, BufferSize)) != 0)
					sendFrameData(buffer, size, &counter);
				break;
			}
			
			case PONG:
			{
				break;
			}
			
			case CLOSE:
			{ 
				close(); 
				return false;
			}
			
			default:
			{
				close();
				throw Exception("Invalid WebSocket opcode");
			}
		}
	}
}

void WebSocket::sendFrameHeader(opcode_t opcode, uint64_t len, bool fin)
{
	if(!mStream) throw NetException("WebSocket is closed");

	mStream->writeBinary(uint8_t((opcode & 0x0F) | (fin ? 0x80 : 0)));
	if(len < 0x7E)
	{
		mStream->writeBinary(uint8_t((len & 0x7F) | (mSendMask ? 0x80 : 0)));
	}
	else if(len <= 0xFF)
	{
		mStream->writeBinary(uint8_t(0x7E | (mSendMask ? 0x80 : 0)));
		mStream->writeBinary(uint16_t(len));
	}
	else {
		mStream->writeBinary(uint8_t(0x7F | (mSendMask ? 0x80 : 0)));
		mStream->writeBinary(uint64_t(len));
	}
	
	if(mSendMask) 
	{
		Random().readBinary(mSendMaskKey, 4);
		mStream->writeBinary(mSendMaskKey, 4);
	}
}

void WebSocket::sendFrameData(char *buffer, uint64_t size, uint64_t *counter)
{
	if(!mStream) throw NetException("WebSocket is closed");

	if(mSendMask)
	{
		if(!counter)
		{
			for(uint64_t i = 0; i < size; ++i)
				buffer[i]^= mSendMaskKey[i%4];
		}
		else {
			for(uint64_t i = 0; i < size; ++i)
				buffer[i]^= mSendMaskKey[((*counter)++)%4];
		}
	}
	else {
		if(counter) *counter+= size;
	}
	mStream->writeData(buffer, size);
}

void WebSocket::sendFrame(opcode_t opcode, char *buffer, uint64_t size, bool fin)
{
	sendFrameHeader(opcode, size, fin);
	if(size) sendFrameData(buffer, size, NULL);
}

}
