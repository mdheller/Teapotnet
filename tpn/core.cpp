/*************************************************************************
 *   Copyright (C) 2011-2013 by Paul-Louis Ageneau                       *
 *   paul-louis (at) ageneau (dot) org                                   *
 *                                                                       *
 *   This file is part of Teapotnet.                                     *
 *                                                                       *
 *   Teapotnet is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU Affero General Public License as      *
 *   published by the Free Software Foundation, either version 3 of      *
 *   the License, or (at your option) any later version.                 *
 *                                                                       *
 *   Teapotnet is distributed in the hope that it will be useful, but    *
 *   WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the        *
 *   GNU Affero General Public License for more details.                 *
 *                                                                       *
 *   You should have received a copy of the GNU Affero General Public    *
 *   License along with Teapotnet.                                       *
 *   If not, see <http://www.gnu.org/licenses/>.                         *
 *************************************************************************/

#include "tpn/core.h"
#include "tpn/config.h"
#include "tpn/scheduler.h"
#include "tpn/binaryserializer.h"
#include "tpn/crypto.h"
#include "tpn/random.h"
#include "tpn/securetransport.h"
#include "tpn/httptunnel.h"
#include "tpn/user.h"

namespace tpn
{

Core *Core::Instance = NULL;


Core::Core(int port) :
		mThreadPool(4, 16, Config::Get("max_connections").toInt()),
		mLastRequest(0),
		mLastPublicIncomingTime(0)
{
	// Define name
	mName = Config::Get("instance_name");
	if(mName.empty())
	{
		char hostname[HOST_NAME_MAX];
		if(!gethostname(hostname,HOST_NAME_MAX)) 
			mName = hostname;
		
		if(mName.empty() || mName == "localhost")
		{
		#ifdef ANDROID
			mName = String("android.") + String::number(unsigned(pseudorand()%1000), 4);
		#else
			mName = String(".") + String::random(6);
		#endif
			Config::Put("instance_name", mName);
			
			const String configFileName = "config.txt";
			Config::Save(configFileName);
		}
	}
	
	// Create backends
	mBackends.push_back(new StreamBackend(port));
	mBackends.push_back(new DatagramBackend(port));
	mBackends.push_back(new TunnelBackend());
	
	// Start backends
	for(List<Backend*>::iterator it = mBackends.begin();
		it != mBackends.end();
		++it)
	{
		Backend *backend = *it;
		backend->start();
	}
}

Core::~Core(void)
{
	// Delete backends
	for(List<Backend*>::iterator it = mBackends.begin();
		it != mBackends.end();
		++it)
	{
		Backend *backend = *it;
		backend->wait();
		delete backend;
	}
}

String Core::getName(void) const
{
	Synchronize(this);
	return mName;
}

void Core::getAddresses(List<Address> &list) const
{
	Synchronize(this);
	mSock.getLocalAddresses(list);
}

void Core::getKnownPublicAdresses(List<Address> &list) const
{
	Synchronize(this);
	list.clear();
	for(	Map<Address, int>::const_iterator it = mKnownPublicAddresses.begin();
		it != mKnownPublicAddresses.end();
		++it)
	{
		list.push_back(it->first);
	}
}

bool Core::isPublicConnectable(void) const
{
	return (Time::Now()-mLastPublicIncomingTime <= 3600.); 
}

void Core::registerPeering(	const Identifier &peering,
				const Identifier &remotePeering,
		       		const BinaryString &secret,
				Core::Listener *listener)
{
	Synchronize(this);
	
	mPeerings[peering] = remotePeering;
	mSecrets[peering] = secret;
	if(listener) mListeners[peering] = listener;
	else mListeners.erase(peering);
}

void Core::unregisterPeering(const Identifier &peering)
{
	Synchronize(this);
	
	mPeerings.erase(peering);
	mSecrets.erase(peering);
}

bool Core::hasRegisteredPeering(const Identifier &peering)
{
	Synchronize(this);
	return mPeerings.contains(peering);
}

void Core::publish(const Identifier &id, Publisher *publisher)
{
	mPublishers[id].insert(publisher);
}

void Core::unpublish(const Identifier &id, Publisher *publisher)
{
	Map<Identifier, Set<Publisher*> >::iterator it = mPublishers.find(id);
	if(it != mPublishers.end())
	{
		it->second.erase(publisher);
		if(it->second.empty()) 
			mPublishers.erase(it);
	}
}

void Core::subscribe(const Identifier &id, Subscriber *subscriber)
{
	mSubscribers[id].insert(subscriber);
}

void Core::unsubscribe(const Identifier &id, Subscriber *subscriber)
{
	Map<Identifier, Set<Subscriber*> >::iterator it = mSubscribers.find(id);
	if(it != mSubscribers.end())
	{
		it->second.erase(subscriber);
		if(it->second.empty())
			mSubscribers.erase(it);
	}
}

Core::LinkStatus Core::addPeer(Stream *bs, const Address &remoteAddr, const Identifier &peering, bool async)
{
	Assert(bs);
	Synchronize(this);
	
	bool hasPeering = (peering != Identifier::Null);

	if(hasPeering && !mPeerings.contains(peering))
		throw Exception("Added peer with unknown peering");
	
	{
		Desynchronize(this);
		//LogDebug("Core", "Spawning new handler");
		Handler *handler = new Handler(this, bs, remoteAddr);
		if(hasPeering) handler->setPeering(peering);

		if(async)
		{
			mThreadPool.launch(handler);
			return Core::Disconnected;
		}
		else {
			Synchronize(handler);
			mThreadPool.launch(handler);
			
			// Timeout is just a security here
			const double timeout = milliseconds(Config::Get("tpot_read_timeout").toInt());
			if(!handler->wait(timeout*4)) return Core::Disconnected;
			return handler->linkStatus();
		}
	}
}

Core::LinkStatus Core::addPeer(Socket *sock, const Identifier &peering, bool async)
{
	const double timeout = milliseconds(Config::Get("tpot_read_timeout").toInt());
	sock->setTimeout(timeout);
	return addPeer(static_cast<Stream*>(sock), sock->getRemoteAddress(), peering, async);
}

bool Core::hasPeer(const Identifier &peering)
{
	Synchronize(this);
	return mHandlers.contains(peering);
}

bool Core::getInstancesNames(const Identifier &peering, Array<String> &array)
{
	array.clear();
	
	Map<Identifier,Handler*>::iterator it = mHandlers.lower_bound(peering);
	if(it == mHandlers.end() || it->first != peering) return false;
		
	while(it != mHandlers.end() && it->first == peering)
	{
		String name = it->first.getName();
		if(name.empty()) name = "default";
		array.push_back(name);
		++it;
	}
	
	return true;
}

bool Core::isRequestSeen(const Request *request)
{
	Synchronize(this);
	
	String uid;
	request->mParameters.get("uid", uid);
	if(!uid.empty())
	{
		if(mSeenRequests.contains(uid)) return true;
		mSeenRequests.insert(uid);
		
		class RemoveSeenTask : public Task
		{
		public:
			RemoveSeenTask(const String &uid) { this->uid = uid; }
			
			void run(void)
			{
				Synchronize(Core::Instance);
				Core::Instance->mSeenRequests.erase(uid);
				delete this;
			}
			
		private:
			String uid;
		};
		
		Scheduler::Global->schedule(new RemoveSeenTask(uid), 60000);
		return false;
	}
	
	return false;
}

void Core::run(void)
{
	LogDebug("Core", "Starting...");
	
	try {
		while(true)
		{
			Thread::Sleep(0.01);

			Socket *sock = new Socket;
			mSock.accept(*sock);
			
			try {
				Address addr;
				const size_t peekSize = 5;	
				char peekData[peekSize];
				std::memset(peekData, 0, peekSize);
				
				try {
					addr = sock->getRemoteAddress();
					LogDebug("Core::run", "Incoming connection from " + addr.toString());
					
					if(addr.isPublic() && addr.isIpv4()) // TODO: isPublicConnectable() currently reports state for ipv4 only
						mLastPublicIncomingTime = Time::Now();
					
					sock->setTimeout(milliseconds(Config::Get("tpot_timeout").toInt()));
					sock->peekData(peekData, peekSize);
					
					sock->setTimeout(milliseconds(Config::Get("tpot_read_timeout").toInt()));
				}
				catch(const std::exception &e)
				{
					delete sock;
					throw;
				}
			
				Stream *bs = NULL;
				
				if(std::memcmp(peekData, "GET ", 4) == 0
					|| std::memcmp(peekData, "POST ", 5) == 0)
				{
					// This is HTTP, forward connection to HttpTunnel
					bs = HttpTunnel::Incoming(sock);
					if(!bs) continue;
				}
				else {
					bs = sock;
				}
				
				LogInfo("Core", "Incoming peer from " + addr.toString() + " (tunnel=" + (bs != sock ? "true" : "false") + ")");
				addPeer(bs, addr, Identifier::Null, true);	// async
			}
			catch(const std::exception &e)
			{
				LogDebug("Core::run", String("Processing failed: ") + e.what());
			}
		}
	}
	catch(const NetException &e)
	{
		LogDebug("Core::run", e.what());
	}
	
	LogDebug("Core", "Finished");
}

/*
bool Core::sendNotification(const Notification &notification)
{
	Synchronize(this);
	
	Array<Identifier> identifiers;
	
	if(notification.mPeering == Identifier::Null)
	{
		mHandlers.getKeys(identifiers);
	}
	else {
		Map<Identifier,Handler*>::iterator it = mHandlers.lower_bound(notification.mPeering);
		if(it == mHandlers.end() || it->first != notification.mPeering) return false;
			
		Array<Handler*> handlers;
		while(it != mHandlers.end() && it->first == notification.mPeering)
		{
			identifiers.push_back(it->first);
			++it;
		}
	}
	
	for(int i=0; i<identifiers.size(); ++i)
	{
		Handler *handler;
		if(mHandlers.get(identifiers[i], handler))
		{
			Desynchronize(this);
			handler->sendNotification(notification);
		}
	}
	
	return (!identifiers.empty());
}

unsigned Core::addRequest(Request *request)
{
	Synchronize(this);

	{
		Synchronize(request);
		if(!request->mId)
			request->mId = ++mLastRequest;
		
		String uid;
		request->mParameters.get("uid", uid);
		if(uid.empty())
		{
			uid = String::random(16);
			request->mParameters["uid"] = uid;
		}
		
		mSeenRequests.insert(uid);
	}

	Array<Identifier> identifiers;
	if(request->mReceiver == Identifier::Null)
	{
		mHandlers.getKeys(identifiers);
	}
	else {
		Map<Identifier,Handler*>::iterator it = mHandlers.lower_bound(request->mReceiver);
		if(it == mHandlers.end() || it->first != request->mReceiver)
			throw Exception("Request receiver is not connected");
		
		while(it != mHandlers.end() && it->first == request->mReceiver)
		{
			identifiers.push_back(it->first);
			++it;
		}
	}

	if(identifiers.empty()) request->notifyAll();
	else for(int i=0; i<identifiers.size(); ++i)
	{
		if(identifiers[i] == request->mNonReceiver)
			continue;
		
		Handler *handler;
		if(mHandlers.get(identifiers[i], handler))
		{
			Desynchronize(this);
			handler->addRequest(request);
		}
	}
	
	return request->mId;
}

void Core::removeRequest(unsigned id)
{
	Synchronize(this);
  
	Array<Identifier> identifiers;
	mHandlers.getKeys(identifiers);
	
	for(int i=0; i<identifiers.size(); ++i)
	{
		Handler *handler;
		if(mHandlers.get(identifiers[i], handler))
		{
			Desynchronize(this);
			handler->removeRequest(id);
		}
	}
}
*/

bool Core::addHandler(const Identifier &peer, Core::Handler *handler)
{
	Assert(handler != NULL);
	Synchronize(this);
	
	Handler *h = NULL;
	if(mHandlers.get(peer, h))
		return (h == handler);

	mHandlers.insert(peer, handler);
	return true;
}

bool Core::removeHandler(const Identifier &peer, Core::Handler *handler)
{
	Assert(handler != NULL);
	Synchronize(this);
  
	Handler *h = NULL;
	if(!mHandlers.get(peer, h) || h != handler)
		return false;
	
	mHandlers.erase(peer);
	return true;
}

bool Core::addRoute(const Identifier &id, const Identifier &route)
{
	mRoutes.insert(id, route);
	return true;
}

bool Core::getRoute(const Identifier &id, Identifier &route)
{
	Map<Identifier, Identifier>::iterator it = mRoutes.find(id);
	if(it == mRoutes.end()) return false;
	route = it->second;
	return true;
}

Core::Missive::Missive(void) :
	data(1024)
{
	
}

Core::Missive::~Missive(void)
{
	
}

void Core::Missive::prepare(const Identifier &source, const Identifier &target)
{
	this->source = source;
	this->target = target;
	data.clear();
}

void Core::Missive::clear(void)
{
	source.clear();
	target.clear();
	data.clear();
}

void Core::Missive::serialize(Serializer &s) const
{
	// TODO
	s.output(source);
	s.output(target);
	s.output(data);
}

bool Core::Missive::deserialize(Serializer &s)
{
	// TODO
	if(!s.input(source)) return false;
	AssertIO(s.input(target));
	AssertIO(s.input(data));
}

Core::Locator::Locator(const Identifier &id)
{
	identifier = id;
}

Core::Locator::Locator(const Address &addr)
{
	addresses.push_back(addr);
}

Core::Locator::~Locator(void)
{

}

Core::Publisher::Publisher(void)
{

}

Core::Publisher::~Publisher(void)
{
	for(Set<Identifier>::iterator it = mPublishedIds.begin();
		it != mPublishedIds.end();
		++it)
	{
		Core::Instance->unpublish(*it, this);
	}
}

void Core::Publisher::publish(const Identifier &id)
{
	if(!mPublishedIds.contains(id))
	{
		Core::Instance->publish(id, this);
		mPublishedIds.insert(id);
	}
}

void Core::Publisher::unpublish(const Identifier &id)
{
	if(mPublishedIds.contains(id))
	{
		Core::Instance->unpublish(id, this);
		mPublishedIds.erase(id);
	}
}

void Core::Publisher::outgoing(const Missive &missive)
{
	
}

Core::Subscriber::Subscriber(void)
{
	
}

Core::Subscriber::~Subscriber(void)
{
	for(Set<Identifier>::iterator it = mSubscribedIds.begin();
		it != mSubscribedIds.end();
		++it)
	{
		Core::Instance->unsubscribe(*it, this);
	}
}

void Core::Subscriber::subscribe(const Identifier &id)
{
	if(!mSubscribedIds.contains(id))
	{
		Core::Instance->subscribe(id, this);
		mSubscribedIds.insert(id);
	}
}

void Core::Subscriber::unsubscribe(const Identifier &id)
{
	if(mSubscribedIds.contains(id))
	{
		Core::Instance->unsubscribe(id, this);
		mSubscribedIds.erase(id);
	}
}

Core::Backend::Backend(Core *core) :
	mCore(core)
{
	Assert(mCore);
}

Core::Backend::~Backend(void)
{
	
}

void Core::Backend::addIncoming(Stream *stream)
{
	// TODO
	mCore->addPeer(stream);
}

void Core::Backend::run(void)
{
	class MyVerifier : public SecureTransportServer::Verifier
	{
	public:
		Core *core;
		User *user;
		BinaryString peering;
		BinaryString identifier;
		Rsa::PublicKey publicKey;
		
		MyVerifier(Core *core) { this->core = core; this->user = NULL; }
	
		bool verifyName(const String &name, SecureTransport *transport)
		{
			user = User::Get(name);
			if(user)
			{
				SecureTransport::Credentials *creds = getCertificateCredentials(user);
				if(creds) transport->addCredentials(creds);
			}
			
			return true;	// continue handshake anyway
		}
	
		bool verifyPrivateSharedKey(const String &name, BinaryString &key)
		{
			try {
				peering.fromString(name);
			}
			catch(...)
			{
				return false;
			}
			
			// TODO: set identifier
			
			BinaryString secret;
			if(SynchronizeTest(core, core->mSecrets.get(peering, secret)))
			{
				key = secret;
				return true;
			}
			else {
				return false;
			}
		}
		
		bool verifyCertificate(const Rsa::PublicKey &pub)
		{
			if(!user) return false;
			
			// TODO: Compute identifier and check against user
			publicKey = pub;
		}
	};
	
	try {
		while(true)
		{
			SecureTransport *transport = listen();
			if(!transport) break;
			
			// TODO: should allocate to threadpool
			
			// set verifier
			MyVerifier verifier(mCore);
			transport->setVerifier(&verifier);
			
			// set credentials (certificate added on name verification)
			transport->addCredentials(getAnonymousCredentials());
			transport->addCredentials(getPrivateSharedKeyCredentials());
			
			// do handshake
			transport->handshake();
			
			// TODO: read credentials and feed them to addIncoming
			// Identifier::Null if transport->isAnonymous()
			// verifier.identifier otherwise
			
			if(transport) addIncoming(transport);
		}
	}
	catch(const std::exception &e)
	{
		LogError("Core::Backend::run", e.what());
	}
	
	LogWarn("Core::Backend::run", "Closing backend");
}

Core::StreamBackend::StreamBackend(int port) :
	mSock(port)
{

}

Core::StreamBackend::~StreamBackend(void)
{
	
}

SecureTransport *Core::StreamBackend::connect(const Locator &locator)
{
	for(List<Address>::iterator it = locator.addresses.begin();
		it != locator.addresses.end();
		++it)
	{
		try {
			return connect(*it);
		}
		catch(const NetException &e)
		{
			LogDebug("Core::StreamBackend::connect", e.what());
		}
	}
}

SecureTransport *Core::StreamBackend::connect(const Address &addr)
{
	Socket *sock = new Socket(addr);
	try {
		SecureTransport *transport = new SecureTransportClient(sock, NULL, false);			// stream mode
		addIncoming(transport);
	}
	catch(...)
	{
		delete sock;
		throw;
	}
}

SecureTransport *Core::StreamBackend::listen(void)
{
	while(true)
	{
		SecureTransport *transport = new SecureTransportServer::Listen(mSock);
		if(transport) return transport;
	}
}

Core::DatagramBackend::DatagramBackend(int port) :
	mSock(port)
{
	
}

Core::DatagramBackend::~DatagramBackend(void)
{
	
}

SecureTransport *Core::DatagramBackend::connect(const Locator &locator)
{
	for(List<Address>::iterator it = locator.addresses.begin();
		it != locator.addresses.end();
		++it)
	{
		try {
			return connect(*it);
		}
		catch(const NetException &e)
		{
			LogDebug("Core::DatagramBackend::connect", e.what());
		}
	}
}

SecureTransport *Core::DatagramBackend::connect(const Address &addr)
{
	DatagramStream *stream = new DatagramStream(&mSock, addr);
	try {
		SecureTransport *transport = new SecureTransportClient(stream, NULL, true);		// datagram mode
		return transport;
	}
	catch(...)
	{
		delete stream;
		throw;
	}
}

SecureTransport *Core::DatagramBackend::listen(void)
{
	while(true)
	{
		SecureTransport *transport = new SecureTransportServer::Listen(mSock);
		if(transport) return transport;
	}
}

TunnelBackend::TunnelBackend(void) :
	Subscriber(Identifier::Null)	// subscribe to everything delegated
{

}

TunnelBackend::~TunnelBackend(void)
{
	
}

SecureTransport *TunnelBackend::connect(const Locator &locator)
{
	Identifier remote = locator.identifier;
	Identifier local = Identifier::Random();

	TunnelWrapper *wrapper = NULL;
	SecureTransport *transport = NULL;
	try {
		wrapper = new TunnelWrapper(local, remote);
		transport = new SecureTransportServer(wrapper, NULL, true);	// datagram mode
	}
	catch(...)
	{
		delete wrapper;
		throw;
	}
	
	return transport;
}

SecureTransport *TunnelBackend::listen(void)
{
	Synchronizable(&mQueueSync);
	while(mQueue.empty()) mQueueSync.wait();
	
	Missive &missive = mQueue.front();
	Assert(missive.type() == Missive::Tunnel);
	
	TunnelWrapper *wrapper = NULL;
	SecureTransport *transport = NULL;
	try {
		wrapper = new TunnelWrapper(missive.target, missive.source);
		transport = new SecureTransportServer(sock, NULL, true);	// datagram mode
	}
	catch(...)
	{
		delete wrapper;
		mQueue.pop();
		throw;
	}
	
	mQueue.pop();
	return transport;
}

bool Core::TunnelWrapper::incoming(Missive &missive)
{
	if(missive.type() == Missive::Tunnel)
	{
		Synchronizable(&mQueueSync);
		mQueue.push(missive);
		return true;
	}
	
	return false;
}

Core::Handler::Handler(Core *core, Stream *stream) :
	mCore(core),
	mStream(stream),
	mSender(NULL),
	mIsIncoming(true),
	mIsRelay(false),
	mIsRelayEnabled(Config::Get("relay_enabled").toBool()),
	mThreadPool(0, 1, 8),
	mStopping(false)
{

}

Core::Handler::~Handler(void)
{
	delete mSender;
	delete mStream;
}

void Core::Handler::setPeering(const Identifier &peering, bool relayed)
{
	Synchronize(this);
	
	mPeering = peering;
	mIsRelay = relayed;
	
	if(peering == Identifier::Null) mIsIncoming = true;
	else {
		mIsIncoming = false;
		if(mPeering.getName().empty())
		{
			LogWarn("Core::Handler", "setPeering() called with undefined instance");
			mPeering.setName("default");
		}
	}
}

void Core::Handler::setStopping(void)
{
	Synchronize(this);
	mStopping = true;
}

/*
void Core::Handler::sendNotification(const Notification &notification)
{
	{
		Synchronize(this);
		if(mStopping) return;
		
		//LogDebug("Core::Handler", "Sending notification");
	}
	
	if(mSender)
	{
		Synchronize(mSender);
		mSender->mNotificationsQueue.push(notification);
		mSender->notify();
	}
}

void Core::Handler::addRequest(Request *request)
{
	{
		Synchronize(this);
		if(mStopping) return;
		
		//LogDebug("Core::Handler", "Adding request " + String::number(request->mId));
		
		request->addPending(mPeering);
		mRequests.insert(request->mId, request);
	}
	
	if(mSender)
	{
		Synchronize(mSender);
		
		Sender::RequestInfo requestInfo;
		requestInfo.id = request->mId;
		requestInfo.target = request->target();
		requestInfo.parameters = request->mParameters;
		requestInfo.isData = request->mIsData;
		mSender->mRequestsQueue.push(requestInfo);
	
		mSender->notify();
	}
}

void Core::Handler::removeRequest(unsigned id)
{
	Synchronize(this);
	if(mStopping) return;
	
	Map<unsigned, Request*>::iterator it = mRequests.find(id);
	if(it != mRequests.end())
	{
		//LogDebug("Core::Handler", "Removing request " + String::number(id));
	
		Request *request = it->second;
		Synchronize(request);
	
		for(int i=0; i<request->responsesCount(); ++i)
		{
			Request::Response *response = request->response(i);
			if(response->mChannel) mResponses.erase(response->mChannel);
		}
		
		request->removePending(mPeering);
		mRequests.erase(it);
	}
	
	
}
*/

bool Core::Handler::isIncoming(void) const
{
	return mIsIncoming;
}

/*
void Core::Handler::clientHandshake(void)
{
	Assert(!mPeering.empty());
	
	if(SynchronizeTest(mCore, !mCore->mPeerings.get(mPeering, mRemotePeering)))
		throw Exception("Peering is not registered");
	
	mRemotePeering.setName(mCore->getName());
	
	if(!mIsRelay)
	{
		BinaryString secret;
		if(SynchronizeTest(mCore, !mCore->mSecrets.get(mPeering, secret)))
			throw Exception("No secret for peering");
		
		String name = mRemotePeering.getDigest().toString();
		mStream = new SecureTransportClient(mStream, new SecureTransportClient::PrivateSharedKey(name, secret));
	}
	else {
		mStream = new SecureTransportClient(mStream, new SecureTransportClient::PrivateSharedKey("anonymous", "anonymous"));
	}
	
	String args;
	args << mRemotePeering;
	StringMap parameters;
	parameters["application"] << APPNAME;
	parameters["version"] << APPVERSION;
	parameters["instance"] << mPeering.getName();
	parameters["relay"] << false;
	sendCommand(mStream, "H", args, parameters);
	
	String command;
	DesynchronizeStatement(this, AssertIO(recvCommand(mStream, command, args, parameters)));
	if(command == "Q") return;
	if(command != "H") throw Exception("Unexpected command: " + command);
	
	String appname, appversion, instance, target;
	args >> target;
	parameters["application"] >> appname;
	parameters["version"] >> appversion;
	parameters.get("instance", instance);
	
	Identifier peering;
	if(target.size() >= 32) target.extract(peering);
	
	// TODO
	mIsRelayEnabled = (!parameters.contains("relay") || parameters["relay"].toBool());
	
	if(mIsRelay)
	{
		mIsRelay = false;
		clientHandshake();
	}
}	

void Core::Handler::serverHandshake(void)
{
	class Callback : public SecureTransportServer::PrivateSharedKeyCallback
	{
	public:
		Core *core;
		BinaryString peering;
		
		bool callback(const String &name, BinaryString &key)
		{
			// Anonymous account
			if(name.toLower() == "anonymous")
			{
				key = "anonymous";
				return true;
			}
			
			try {
				peering.fromString(name);
			}
			catch(...)
			{
				return false;
			}
			
			BinaryString secret;
			if(SynchronizeTest(core, core->mSecrets.get(peering, secret)))
			{	
				key = secret;
				return true;
			}
			else {
				return false;
			}
		}
	};
	
	Callback *cb = new Callback;
	cb->core = mCore;
	mStream = new SecureTransportServer(mStream, cb);
	mPeering = cb->peering;
	
	if(!mPeering.empty())
	{
		if(SynchronizeTest(mCore, !mCore->mPeerings.get(mPeering, mRemotePeering)))
			throw Exception("Peering is not registered");
	
		mRemotePeering.setName(mCore->getName());
	}
	else {
		mIsRelay = true;
	}
	
	String command;
	String args;
	StringMap parameters;
	DesynchronizeStatement(this, AssertIO(recvCommand(mStream, command, args, parameters)));
	if(command == "Q") return;
	if(command != "H") throw Exception("Unexpected command: " + command);
	
	String appname, appversion, instance, target;
	args >> target;
	parameters["application"] >> appname;
	parameters["version"] >> appversion;
	parameters.get("instance", instance);
	
	Identifier peering;
	if(target.size() >= 32) target.extract(peering);
	
	mLinkStatus = Established;	// Established means TLS hanshake was performed (possibly anonymously)
	
	if(!mIsRelay)
	{
		if(mPeering != peering) 
			throw Exception("Peering does not match");
	}
	else {
		mPeering = peering;
		
		if(mPeering.empty())
			throw Exception("Expected peering");
		
		if(mPeering.getName().empty())
		{
			LogWarn("Core::Handler", "Got peering with undefined instance");
			mPeering.setName("default");
		}
		
		if((!instance.empty() && instance != mCore->getName())
			|| SynchronizeTest(mCore, !mCore->mPeerings.get(mPeering, mRemotePeering)))
		{
			Desynchronize(this);
			
			Synchronizable *meeting = &mCore->mMeetingPoint;
			Synchronize(meeting);
			
			if(!Config::Get("relay_enabled").toBool()) 
			{
				Desynchronize(meeting);
				sendCommand(mStream, "Q", String::number(NotFound), StringMap());
				return;
			}
			
			const double meetingStepTimeout = milliseconds(std::min(Config::Get("meeting_timeout").toInt()/3, Config::Get("request_timeout").toInt()));
			double timeout = meetingStepTimeout;
			while(timeout > 0.)
			{
				if(SynchronizeTest(mCore, mCore->mRedirections.contains(mPeering))) break;
				if(!meeting->wait(timeout)) break;
			}
			
			Handler *handler = NULL;
			if(SynchronizeTest(mCore, mCore->mRedirections.get(mPeering, handler)))
			{
				if(handler)
				{
					Desynchronize(meeting);
					LogDebug("Core::Handler", "Connection already forwarded");
					sendCommand(mStream, "Q", String::number(RedirectionExists), StringMap());
					return;
				}
				
				//Log("Core::Handler", "Reached forwarding meeting point");
				SynchronizeStatement(mCore, mCore->mRedirections.insert(mPeering, this));
				meeting->notifyAll();
				
				timeout = meetingStepTimeout;
				while(timeout > 0.)
				{
					if(!mStream) break;
					if(!meeting->wait(timeout)) break;
				}
				
				SynchronizeStatement(mCore, mCore->mRedirections.erase(mPeering));
				if(mStream) sendCommand(mStream, "Q", String::number(RedirectionFailed), StringMap());
				return;
			}
			
			LogDebug("Core::Handler", "Asking peers for redirection target peering");
			
			String adresses;
			List<Address> list;
			Config::GetExternalAddresses(list);
			for(	List<Address>::iterator it = list.begin();
				it != list.end();
				++it)
			{
				if(!adresses.empty()) adresses+= ',';
				adresses+= it->toString();
			}
				
			Request request(String("peer:") + mPeering.toString(), false);
			request.setParameter("adresses", adresses);
			if(!instance.empty()) request.setParameter("instance", instance);
			request.submit();
			request.wait(meetingStepTimeout);
			request.cancel();

			String remote;
			for(int i=0; i<request.responsesCount(); ++i)
			{
				if(!request.response(i)->error() && request.response(i)->parameter("remote", remote))
					break;
			}
			
			if(remote.empty())
			{
				Desynchronize(meeting);
				sendCommand(mStream, "Q", String::number(NotFound), StringMap());
				return;
			}
			
			LogDebug("Core::Handler", "Got positive response for peering");
				
			remote >> mRemotePeering;
			SynchronizeStatement(mCore, mCore->mRedirections.insert(mRemotePeering, NULL));
			
			Handler *otherHandler = NULL;
			
			meeting->notifyAll();
			timeout = meetingStepTimeout;
			while(timeout > 0.)
			{
				SynchronizeStatement(mCore, mCore->mRedirections.get(mRemotePeering, otherHandler));
				if(otherHandler) break;
				if(!meeting->wait(timeout)) break;
			}
			
			if(otherHandler && otherHandler->mStream)
			{
				Stream     *otherStream    = otherHandler->mStream;
				otherHandler->mStream      = NULL;
				
				meeting->notifyAll();
				
				if(mStream)
				{
					Desynchronize(meeting);
					LogInfo("Core::Handler", "Successfully forwarded connection");
					
					// Answer
					args.clear();
					args << "anonymous";
					parameters.clear();
					parameters["application"] << APPNAME;
					parameters["version"] << APPVERSION;
					parameters["relay"] << mIsRelayEnabled;
					sendCommand(mStream, "H", args, parameters);
					
					// Transfer
					Stream::Transfer(mStream, otherStream);
				}
				
				delete otherStream;
			}
			else {
				Desynchronize(meeting);
				LogWarn("Core::Handler", "No other handler reached forwarding meeting point");
				sendCommand(mStream, "Q", String::number(RedirectionFailed), StringMap());
			}
				
			SynchronizeStatement(mCore, mCore->mRedirections.erase(mPeering));	
			return;
		}
	}
	
	if(mPeering == mRemotePeering && mPeering.getName() == mCore->getName())
		throw Exception("Tried to connect same user on same instance");
		
	args.clear();
	args << mRemotePeering;
	parameters.clear();
	parameters["application"] << APPNAME;
	parameters["version"] << APPVERSION;
	parameters["instance"] << mPeering.getName();
	parameters["relay"] << mIsRelayEnabled;
	sendCommand(mStream, "H", args, parameters);
}
*/

bool Core::Handler::recv(Missive &missive)
{
	BinarySerializer(mStream);
	return serializer.read(missive);
}

void Core::Handler::send(const Missive &missive)
{
	BinarySerializer(mStream);
	serializer.write(missive);
}

void Core::Handler::process(void)
{
	String command, args;
	StringMap parameters;
  
	Synchronize(this);
	LogDebug("Core::Handler", "Starting...");
	
	Missive missive;
	JsonSerializer json(&missive.data);
	
	missive.prepare(mLocal, mRemote);
	// TODO
	
	while(recv(missive))
	{
		try {
			Map<Identifier, Set<Subscriber*> >::iterator it = mSubscribers.find(missive.target);
			if(it != mSubscribers.end())
			{
				for(Set<Subscriber*>::iterator jt = it->second.begin();
					jt != it->second.end();
					++jt)
				{
					jt->subscribe(*jt);
				}	
			}
			
			// TODO: when to forward ?
			route(missive);
		}
		catch(const std::exception &e)
		{
			LogWarn("Core::Handler", e.what()); 
			return;
		}
	}
	
	Identifier peering;
	SynchronizeStatement(this, peering = mPeering);
	
	try {
		// Register the handler
                if(!mCore->addHandler(mPeering, this))
                {
                        LogInfo("Core::Handler", "Duplicate handler for the peering, exiting.");
                        return;
                }
		
		// WARNING: Do not simply return after this point, sender is starting
		notifyAll();
		
		// Start the sender
		mSender = new Sender;
		mSender->mStream = mStream;
		mSender->start();
		Thread::Sleep(0.1);
		
		Listener *listener = NULL;
		if(SynchronizeTest(mCore, mCore->mListeners.get(peering, listener)))
		{
			try {
				listener->connected(peering, mIsIncoming);
			}
			catch(const Exception &e)
			{
				LogWarn("Core::Handler", String("Listener connected callback failed: ")+e.what());
			}
		}

		// Main loop
		LogDebug("Core::Handler", "Entering main loop");
		while(recvCommand(mStream, command, args, parameters))
		{
			Synchronize(this);

			if(command == "K")	// Keep Alive
			{
				String dummy;
				Assert(args.read(dummy));
			}
			else if(command == "R")	// Response
			{
				unsigned id;
				int status;
				unsigned channel;
				Assert(args.read(id));
				Assert(args.read(status));
				Assert(args.read(channel));
				
				Request *request;
				if(mRequests.get(id,request))
				{
					Synchronize(request);
				  
				  	Request::Response *response;
					if(channel)
					{
						//LogDebug("Core::Handler", "Received response for request "+String::number(id)+", status "+String::number(status)+", receiving on channel "+String::number(channel));
	
						Stream *sink = NULL;
						if(request->mContentSink)
						{
							if(!request->hasContent())
								sink = request->mContentSink;
						}
						else sink = new TempFile;
						
						response = new Request::Response(status, parameters, sink);
						response->mChannel = channel;
						if(sink) 
						{
							mResponses.insert(channel, response);
							mCancelled.clear();
						}
					}
					else {
						//LogDebug("Core::Handler", "Received response for request "+String::number(id)+", status "+String::number(status)+", no data");
						response = new Request::Response(status, parameters);
					}

					response->mPeering = peering;
					request->addResponse(response);
					if(response->status() != Request::Response::Pending) 
						request->removePending(peering);	// this triggers the notification
				}
				else LogDebug("Core::Handler", "Received response for unknown request "+String::number(id));
			}
			else if(command == "D")	// Data block
			{
				unsigned channel;
				Assert(args.read(channel));
				
				unsigned size = 0;
				if(parameters.contains("length")) parameters["length"].extract(size);

				Request::Response *response;
				if(mResponses.get(channel,response))
				{
				 	Assert(response->content());
					if(size) {
					  	size_t len = mStream->readData(*response->content(), size);
						if(len != size) throw IOException("Incomplete data chunk");
					}
					else {
						LogDebug("Core::Handler", "Finished receiving on channel "+String::number(channel));
						response->content()->close();
						response->mStatus = Request::Response::Finished;
						mResponses.erase(channel);
					}
				}
				else {
					AssertIO(mStream->ignore(size));
					
					if(mCancelled.find(channel) == mCancelled.end())
					{
						mCancelled.insert(channel);
					  
						args.clear();
						args.write(channel);
						parameters.clear();
						
						Desynchronize(this);
						LogDebug("Core::Handler", "Sending cancel on channel "+String::number(channel));
						SynchronizeStatement(mSender, Handler::sendCommand(mStream, "C", args, parameters));
					}
				}
			}
			else if(command == "E")	// Error
			{
				unsigned channel;
				int status;
				Assert(args.read(channel));
				Assert(args.read(status));
				
				Request::Response *response;
				if(mResponses.get(channel,response))
				{
				 	Assert(response->content() != NULL);
					
					LogDebug("Core::Handler", "Error on channel "+String::number(channel)+", status "+String::number(status));
					
					Assert(status > 0);
				
					response->mStatus = status;
					response->content()->close();
					mResponses.erase(channel);
				}
				//else LogDebug("Core::Handler", "Received error for unknown channel "+String::number(channel));
			}
			else if(command == "C")	// Cancel
			{
				unsigned channel;
				Assert(args.read(channel));
				
				Synchronize(mSender);
				Request::Response *response;
				if(mSender->mTransferts.get(channel, response))
				{
					LogDebug("Core::Handler", "Received cancel for channel "+String::number(channel));
					response->mTransfertFinished = true;
					mSender->mTransferts.erase(channel);
				}
				//else LogDebug("Core::Handler", "Received cancel for unknown channel "+String::number(channel));
			}
			else if(command == "I" || command == "G") // Request
			{
			  	unsigned id;
				Assert(args.read(id));
				String &target = args;
			  	LogDebug("Core::Handler", "Received request "+String::number(id));

				Request *request = new Request(target, (command == "G"));
				request->setParameters(parameters);
				request->mRemoteId = id;
				request->mRemoteAddr = mRemoteAddr;
				
				if(mCore->isRequestSeen(request))
				{
					request->addResponse(new Request::Response(Request::Response::AlreadyResponded));
		
					Synchronize(mSender);	
					mSender->mRequestsToRespond.push_back(request);
					request->mResponseSender = mSender;
					mSender->notify();
					continue;
				}
				
				Listener *listener = NULL;
				if(!SynchronizeTest(mCore, mCore->mListeners.get(peering, listener)))
				{
					LogDebug("Core::Handler", "No listener for request " + String::number(id));
				}
				
				class RequestTask : public Task
				{
				public:
					RequestTask(	const Identifier &peering,
							Listener *listener,
							Request *request, 
							Sender *sender)
					{
						this->peering = peering;
						this->listener = listener;
						this->request = request;
						this->sender = sender;
					}
					
					void run(void)
					{
						try {
							if(listener) listener->request(peering, request);
						}
						catch(const Exception &e)
						{
							LogWarn("RequestTask::run", String("Listener failed to process request "+String::number(request->mRemoteId)+": ") + e.what()); 
						}
						
						try {
							{
								Synchronize(request);
								
								if(request->responsesCount() == 0) 
									request->addResponse(new Request::Response(Request::Response::Failed));
					
								for(int i=0; i<request->responsesCount(); ++i)
								{
									Request::Response *response = request->response(i);
									response->mTransfertStarted = false;
									response->mTransfertFinished = false;
								}
							}
							
							{
								Synchronize(sender);
								
								sender->mRequestsToRespond.push_back(request);
								request->mResponseSender = sender;
								sender->notify();
							}
						}
						catch(const Exception &e)
						{
							LogWarn("RequestTask::run", e.what()); 
						}
						
						delete this;	// autodelete
					}
					
				private:
					Identifier peering;
					Listener *listener;
					Request *request;
					Sender  *sender;
				};
				
				mThreadPool.launch(new RequestTask(peering, listener, request, mSender));
			}
			else if(command == "M")
			{
				unsigned length = 0;
				if(parameters.contains("length")) 
				{
					parameters["length"].extract(length);
					parameters.erase("length");
				}
			  
				//LogDebug("Core::Handler", "Received notification");
				
				Notification notification;
				notification.setParameters(parameters);
				notification.mPeering = mPeering;
				notification.mContent.reserve(length);
				mStream->read(notification.mContent, length);
				
				Listener *listener = NULL;
				if(!SynchronizeTest(mCore, mCore->mListeners.get(peering, listener)))
				{
					LogDebug("Core::Handler", "No listener, dropping notification");
				}
				else {
					try {
						Desynchronize(this);
						if(!listener->notification(peering, &notification)) break;
					}
					catch(const Exception &e)
					{
						LogWarn("Core::Handler", String("Listener failed to process the notification: ") + e.what());
					}
				}
			}
			else if(command == "Q")	// Optionnal, closing the connection is sufficient
			{
				break;
			}
			else {
				LogWarn("Core::Handler", "Unknown command: " + command);

				unsigned length = 0;
				if(parameters.contains("length")) parameters["length"].extract(length);
				if(length) AssertIO(mStream->ignore(length));
			}
			
			if(mStopping) break;
		}

		LogDebug("Core::Handler", "Finished");
	}
	catch(const std::exception &e)
	{
		LogWarn("Core::Handler", e.what()); 
	}

	// Wait for tasks to finish
	mThreadPool.clear();
	
	try {
		Synchronize(this);

		mStopping = true;

		for(Map<unsigned, Request::Response*>::iterator it = mResponses.begin();
			it != mResponses.end();
			++it)
		{
			it->second->mStatus = Request::Response::Interrupted;
			it->second->content()->close();
		}

		for(Map<unsigned, Request*>::iterator it = mRequests.begin();
			it != mRequests.end();
			++it)
		{
			it->second->removePending(mPeering);
		}
	}
	catch(const std::exception &e)
	{
		LogError("Core::Handler", e.what());
	}
	
	try {
		Synchronize(mCore);
		
		mCore->removeHandler(mPeering, this);
		 
		if(mCore->mKnownPublicAddresses.contains(mRemoteAddr))
		{
			mCore->mKnownPublicAddresses[mRemoteAddr]-= 1;
			if(mCore->mKnownPublicAddresses[mRemoteAddr] == 0)
				mCore->mKnownPublicAddresses.erase(mRemoteAddr);
		}
	}
	catch(const std::exception &e)
	{
		LogError("Core::Handler", e.what()); 
	}
	
	Listener *listener = NULL;
	if(SynchronizeTest(mCore, mCore->mListeners.get(peering, listener)))
	{
		try {
			listener->disconnected(peering);
		}
		catch(const Exception &e)
		{
			LogWarn("Core::Handler", String("Listener disconnected callback failed: ") + e.what());
		}
	}
	
	// Stop the sender
	if(mSender && mSender->isRunning())
	{
		SynchronizeStatement(mSender, mSender->mShouldStop = true);
		mSender->notify();
		mSender->join();	
	}
}

void Core::Handler::run(void)
{
	try {
		process();
	}
	catch(const std::exception &e)
	{
		LogWarn("Core::Handler::run", String("Unhandled exception: ") + e.what()); 
	}
	catch(...)
	{
		LogWarn("Core::Handler::run", String("Unhandled unknown exception")); 
	}
		
	notifyAll();
	Thread::Sleep(5.);	// TODO
	delete this;		// autodelete
}

const size_t Core::Handler::Sender::ChunkSize = BufferSize;

Core::Handler::Sender::Sender(void) :
		mLastChannel(0),
		mShouldStop(false)
{

}

Core::Handler::Sender::~Sender(void)
{
	try {
		Map<unsigned, Request::Response*>::iterator it = mTransferts.begin();
		while(it != mTransferts.end())
		{
			int status = Request::Response::Interrupted;	
			String args;
			args << it->first << status;
			Handler::sendCommand(mStream, "E", args, StringMap());
			++it;
		}
	}
	catch(const NetException &e)
	{
		// Nothing to do, the other side will close the transferts anyway
	}
	
	for(int i=0; i<mRequestsToRespond.size(); ++i)
		delete mRequestsToRespond[i];
}

void Core::Handler::Sender::run(void)
{
	try {
		LogDebug("Core::Handler::Sender", "Starting");
		Assert(mStream);
		
		const double readTimeout = milliseconds(Config::Get("tpot_read_timeout").toInt());
		
		while(true)
		{
			Synchronize(this);
			if(mShouldStop) break;

			if(mNotificationsQueue.empty()
				&& mRequestsQueue.empty()
			  	&& mTransferts.empty())
			{
				// Keep Alive
				String args;
				args << unsigned(Random().readInt());
				StringMap parameters;
				DesynchronizeStatement(this, Handler::sendCommand(mStream, "K", args, parameters));

				//LogDebug("Core::Handler::Sender", "No pending tasks, waiting");
				wait(readTimeout/2);
				if(mShouldStop) break;
			}
			
			for(int i=0; i<mRequestsToRespond.size(); ++i)
			{
				Request *request = mRequestsToRespond[i];
				Synchronize(request);
				
				for(int j=0; j<request->responsesCount(); ++j)
				{
					Request::Response *response = request->response(j);
					if(!response->mTransfertStarted)
					{
						unsigned channel = 0;

						response->mTransfertStarted = true;
						if(!response->content()) response->mTransfertFinished = true;
						else {
							++mLastChannel;
							channel = mLastChannel;
							
							LogDebug("Core::Handler::Sender", "Start sending on channel "+String::number(channel));
							mTransferts.insert(channel,response);
						}
						
						LogDebug("Core::Handler::Sender", "Sending response " + String::number(j) + " for request " + String::number(request->mRemoteId));
						
						int status = response->status();
						if(status == Request::Response::Success && j != request->responsesCount()-1)
							status = Request::Response::Pending;
						
						String args;
						args << request->mRemoteId << " " << status << " " <<channel;
						DesynchronizeStatement(this, Handler::sendCommand(mStream, "R", args, response->mParameters));
					}
				}
			}
			
			if(!mNotificationsQueue.empty())
			{
				const Notification &notification = mNotificationsQueue.front();
				unsigned length = notification.content().size();
				
				//LogDebug("Core::Handler::Sender", "Sending notification");

				String args = "";
				StringMap parameters = notification.parameters();
				parameters["length"] << length;
				
				DesynchronizeStatement(this, Handler::sendCommand(mStream, "M", args, parameters));
				DesynchronizeStatement(this, mStream->write(notification.mContent));
				mNotificationsQueue.pop();
			}
			  
			if(!mRequestsQueue.empty())
			{
				const RequestInfo &request = mRequestsQueue.front();
				//LogDebug("Core::Handler::Sender", "Sending request "+String::number(request.id));
				
				String command;
				if(request.isData) command = "G";
				else command = "I";
				
				String args;
				args << request.id << " " << request.target;
				DesynchronizeStatement(this, Handler::sendCommand(mStream, command, args, request.parameters));
				
				mRequestsQueue.pop();
			}

			Array<unsigned> channels;
			mTransferts.getKeys(channels);
			
			for(int i=0; i<channels.size(); ++i)
			{
				SyncYield(this);
			  
				// Check for tasks with higher priority
				if(!mNotificationsQueue.empty()
				|| !mRequestsQueue.empty())
					break;
			  	
				for(int j=0; j<mRequestsToRespond.size(); ++j)
				{
					Synchronize(mRequestsToRespond[j]);
					for(int k=0; k<mRequestsToRespond[j]->responsesCount(); ++k)
						if(!mRequestsToRespond[j]->response(k)->mTransfertStarted) 
							break;
				}
				
				unsigned channel = channels[i];
				Request::Response *response;
				if(!mTransferts.get(channel, response)) continue;
				
				char buffer[ChunkSize];
				size_t size = 0;
				
				try {
					Stream *content = response->content();
					size = content->readData(buffer, ChunkSize);
				}
				catch(const Exception &e)
				{
					LogWarn("Core::Handler::Sender", "Error on channel " + String::number(channel) + ": " + e.what());
					
					response->mTransfertFinished = true;
					mTransferts.erase(channel);
					
					String args;
					args << channel << " " << Request::Response::ReadFailed;
					StringMap parameters;
					parameters["notification"] = e.what();
					DesynchronizeStatement(this, Handler::sendCommand(mStream, "E", args, parameters));
					continue;
				}

				String args;
				args << channel;
				StringMap parameters;
				parameters["length"] << size;
				DesynchronizeStatement(this, Handler::sendCommand(mStream, "D", args, parameters));

				if(size == 0)
				{
					LogDebug("Core::Handler::Sender", "Finished sending on channel "+String::number(channel));
					response->mTransfertFinished = true;
					mTransferts.erase(channel);
				}
				else {
				 	DesynchronizeStatement(this, mStream->writeData(buffer, size));
				}
			}
			
			for(int i=0; i<mRequestsToRespond.size(); ++i)
			{
				Request *request = mRequestsToRespond[i];
				
				{
					Synchronize(request);
					
					if(request->isPending()) continue;

					bool finished = true;
					for(int j=0; j<request->responsesCount(); ++j)
					{
						Request::Response *response = request->response(j);
						finished&= response->mTransfertFinished;
					}

					if(!finished) continue;
				}
				
				if(!request->mId) delete request;
				mRequestsToRespond.erase(i);
			}
		}
		
		LogDebug("Core::Handler::Sender", "Finished");
	}
	catch(const std::exception &e)
	{
		LogError("Core::Handler::Sender", e.what()); 
	}
}

}
