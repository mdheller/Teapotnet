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

#ifndef ARC_CORE_H
#define ARC_CORE_H

#include "include.h"
#include "address.h"
#include "stream.h"
#include "serversocket.h"
#include "socket.h"
#include "pipe.h"
#include "thread.h"
#include "mutex.h"
#include "signal.h"
#include "identifier.h"
#include "request.h"
#include "synchronizable.h"
#include "map.h"
#include "array.h"
#include "http.h"
#include "interface.h"

namespace arc
{

class Core : public Thread, public HttpInterfaceable
{
public:
	static Core *Instance;
	
	Core(int port);
	~Core(void);
	
	void addPeer(Socket *sock, const Identifier &peering, const Identifier &remotePeering);
	bool hasPeer(const Identifier &peering);
	
	unsigned addRequest(Request *request);
	void removeRequest(unsigned id);

	void http(const String &prefix, Http::Request &request);

private:
	void run(void);

	class Handler : public Thread, public Synchronizable
	{
	public:
		Handler(Core *core, Socket *sock);
		~Handler(void);

		void setPeering(const Identifier &peering, const Identifier &remotePeering);
		
		void addRequest(Request *request);
		void removeRequest(unsigned id);

	protected:
	  	static void sendCommand(Socket *sock,
				   	const String &command, 
		       			const String &args,
					const StringMap &parameters);
		
		static bool recvCommand(Socket *sock,
				   	String &command, 
		       			String &args,
					StringMap &parameters);
		
	private:
		void run(void);

		Identifier mPeering, mRemotePeering;
		Core	*mCore;
		Socket  *mSock;
		Handler *mHandler;
		Map<unsigned, Request*> mRequests;
		Map<unsigned, Request::Response*> mResponses;

		class Sender : public Thread, public Synchronizable
		{
		public:
			Sender(Socket *sock);
			~Sender(void);

		private:
			static const size_t ChunkSize;

			void run(void);

			Socket  *mSock;
			unsigned mLastChannel;
			Map<unsigned, ByteStream*> mTransferts;	// TODO
			Queue<Request*> mRequestsQueue;
			Array<Request*> mRequestsToRespond;
			friend class Handler;
		};

		Sender mSender;
	};

	void add(const Identifier &peer, Handler *Handler);
	void remove(const Identifier &peer);

	String mLocalName;
	ServerSocket mSock;
	Map<ByteString, ByteString > mSecrets;
	Map<Identifier,Handler*> mPeers;
	Map<unsigned,Request*> mRequests;
	unsigned mLastRequest;

	friend class Handler;
};

}

#endif
