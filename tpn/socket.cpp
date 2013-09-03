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

#include "tpn/socket.h"
#include "tpn/exception.h"
#include "tpn/config.h"
#include "tpn/http.h"

namespace tpn
{

void Socket::Transfert(Socket *sock1, Socket *sock2)
{
	Assert(sock1);
	Assert(sock2);
  
	char buffer[BufferSize];
	
	while(true)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(sock1->mSock, &readfds);
		FD_SET(sock2->mSock, &readfds);
		
		int n = std::max(SOCK_TO_INT(sock1->mSock),SOCK_TO_INT(sock2->mSock))+1;
		int ret = ::select(n, &readfds, NULL, NULL, NULL);

		if (ret < 0) throw Exception("Unable to wait on socket");
		if (ret ==  0) break;
		
		if(FD_ISSET(sock1->mSock, &readfds))
		{
			 int count = ::recv(sock1->mSock, buffer, BufferSize, 0);
			 if(count <= 0) break;
			 sock2->writeData(buffer, count);
		}
		
		if(FD_ISSET(sock2->mSock, &readfds))
		{
			 int count = ::recv(sock2->mSock, buffer, BufferSize, 0);
			 if(count <= 0) break;
			 sock1->writeData(buffer, count);
		}
	}
	
	sock1->close();
	sock2->close();
}
  
Socket::Socket(void) :
		mSock(INVALID_SOCKET),
		mTimeout(-1.)
{

}

Socket::Socket(const Address &a, double timeout) :
		mSock(INVALID_SOCKET),
		mTimeout(timeout)
{
	connect(a);
}

Socket::Socket(socket_t sock) :
		mTimeout(-1.)
{
	mSock = sock;
}

Socket::~Socket(void)
{
	close();
}

bool Socket::isConnected(void) const
{
	return (mSock != INVALID_SOCKET);
}

Address Socket::getRemoteAddress(void) const
{
	if(!mProxifiedAddr.isNull()) return mProxifiedAddr;

	sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	if(getpeername(mSock, reinterpret_cast<sockaddr*>(&addr), &len))
		throw NetException("Unable to retrieve remote address");

	return Address(reinterpret_cast<sockaddr*>(&addr), len);
}

void Socket::setTimeout(double timeout)
{
	mTimeout = timeout;
	
	struct timeval tv;
	Time::SecondsToStruct(mTimeout, tv);
	setsockopt(mSock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&tv), sizeof(tv));
	setsockopt(mSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&tv), sizeof(tv));	
}

void Socket::connect(const Address &addr, bool noproxy)
{
	String proxy = Config::Get("http_proxy").trimmed();
	if(!noproxy && !proxy.empty() && Config::Get("http_proxy_connect").toBool())
	{
		connect(Address(proxy), true);
		
		uint16_t port = addr.port();
		try {
			String target = addr.toString();
			Http::Request request(target, "CONNECT");
			request.version = "1.1";
			request.headers["Host"] = target;
			request.send(*this);
		
			Http::Response response;
			response.recv(*this);
			if(response.code != 200)
			{
				String msg = String::number(response.code) + " " + response.message;
				LogWarn("Socket::connect", String("HTTP proxy error: ") + msg);
				throw Exception(msg);
			}
		}
		catch(const Exception &e)
		{
			close();
			throw NetException(String("Connection to ") + addr.toString() + " with proxy failed: " + e.what());
		}

		mProxifiedAddr = addr;
	}
	else try {

		close();
	  
		// Create socket
		mSock = ::socket(addr.addrFamily(),SOCK_STREAM,0);
		if(mSock == INVALID_SOCKET)
			throw NetException("Socket creation failed");

		if(mTimeout > 0.)
		{
			ctl_t b = 1;
			if(ioctl(mSock,FIONBIO,&b) < 0)
				throw Exception("Cannot set non-blocking mode");
		
			// Initiate connection
			::connect(mSock, addr.addr(), addr.addrLen());
			
			fd_set writefds;
			FD_ZERO(&writefds);
			FD_SET(mSock, &writefds);

			struct timeval tv;
			Time::SecondsToStruct(mTimeout, tv);
			int ret = ::select(SOCK_TO_INT(mSock)+1, NULL, &writefds, NULL, &tv);

			if (ret == -1) 
				throw Exception("Unable to wait on socket");
			
			if (ret ==  0 || ::send(mSock, NULL, 0, 0) != 0)
				throw NetException(String("Connection to ")+addr.toString()+" failed"); 
		
			b = 0;
                	if(ioctl(mSock,FIONBIO,&b) < 0)
                        	throw Exception("Cannot set blocking mode");
			
			setTimeout(mTimeout);
		}
		else {
			// Connect it
			if(::connect(mSock,addr.addr(), addr.addrLen()) != 0)
				throw NetException(String("Connection to ")+addr.toString()+" failed");
		}
	}
	catch(...)
	{
		close();
		throw;
	}
}

void Socket::close(void)
{
	if(mSock != INVALID_SOCKET)
	{
		::closesocket(mSock);
		mSock = INVALID_SOCKET;
	}

	mProxifiedAddr.setNull();
}

size_t Socket::readData(char *buffer, size_t size)
{
	if(mTimeout > 0.)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(mSock, &readfds);

		struct timeval tv;
		Time::SecondsToStruct(mTimeout, tv);
		int ret = ::select(SOCK_TO_INT(mSock)+1, &readfds, NULL, NULL, &tv);

		if (ret == -1) throw Exception("Unable to wait on socket");
		if (ret ==  0) throw Timeout();
	}
	
	int count = ::recv(mSock,buffer,size,0);
	if(count < 0) throw NetException("Connection lost");
	if(sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) throw Timeout();
	return count;
}

void Socket::writeData(const char *data, size_t size)
{
	while(size)
	{
		int count = ::send(mSock, data, size, 0);
		if(count == 0) throw NetException("Connection closed");
		if(count < 0)  throw NetException("Connection lost");
		if(sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) throw Timeout();
		
		data+= count;
		size-= count;
	}
}

}
