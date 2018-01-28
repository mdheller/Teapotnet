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

#ifndef PLA_WEBSOCKET_H
#define PLA_WEBSOCKET_H

#include "pla/include.hpp"
#include "pla/string.hpp"
#include "pla/http.hpp"
#include "pla/stream.hpp"

namespace pla
{

class WebSocket : public Stream
{
public:
	static WebSocket *Upgrade(Http::Request &request, bool binary = false);
	
	WebSocket(void);
	WebSocket(const String &url, bool binary = false);
	WebSocket(Stream *stream, bool binary = false, bool disableMask = false);
	virtual ~WebSocket(void);

	void connect(const String &url, bool binary = false);
	void close(void);

	// Stream
	size_t readData(char *buffer, size_t size);
	void writeData(const char *data, size_t size);
	bool waitData(duration timeout);
	bool nextRead(void);
	bool nextWrite(void);
	void setTimeout(duration timeout);
	
protected:
	enum opcode_t : uint8_t
	{
		CONTINUATION = 0x0,
		TEXT_FRAME = 0x1,
		BINARY_FRAME = 0x2,
		CLOSE = 0x8,
		PING = 0x9,
		PONG = 0xA,
	};
	
	bool recvFrame(void);
	void sendFrameHeader(opcode_t opcode, uint64_t len, bool fin);
	void sendFrameData(char *buffer, uint64_t size, uint64_t *counter = NULL);
	void sendFrame(opcode_t opcode, char *buffer, uint64_t size, bool fin);
	
private:
	void init(void);
	
	Stream *mStream;
	uint64_t mLength;
	uint64_t mLeft;
	char mMaskKey[4];
	char mSendMaskKey[4];
	bool mIsBinary;
	bool mFin;
	bool mMask;
	bool mSendMask;
	bool mSendContinuation;
};

}

#endif
