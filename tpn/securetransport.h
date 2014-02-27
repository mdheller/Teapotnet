/*************************************************************************
 *   Copyright (C) 2011-2014 by Paul-Louis Ageneau                       *
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

#ifndef TPN_SECURETRANSPORT_H
#define TPN_SECURETRANSPORT_H

#include "tpn/include.h"
#include "tpn/stream.h"
#include "tpn/string.h"
#include "tpn/map.h"
#include "tpn/mutex.h"

#include <gnutls/gnutls.h>

namespace tpn
{
	
class SecureTransport : public Stream
{
public:
	static void Init(void);
	static void Cleanup(void);

	class Credentials
	{
	public:
		Credentials(void) {}
		virtual ~Credentials(void) {}
		void install(SecureTransport *st);
		
	protected:
		virtual void install(gnutls_session_t session) = 0;
	};
	
	void handshake(Credentials *creds);	// creds will be deleted
	void close(void);
	
	size_t readData(char *buffer, size_t size); 
	void writeData(const char *data, size_t size);

protected:
	SecureTransport(bool server, Stream *stream, Credentials *creds);	// stream and creds will be deleted
	virtual ~SecureTransport(void);
	
	gnutls_session_t mSession;

private:
	static ssize_t ReadCallback(gnutls_transport_ptr_t ptr, void* data, size_t maxlen);
	static ssize_t WriteCallback(gnutls_transport_ptr_t ptr, void* data, size_t len);
	
	Stream *mStream;	
	Credentials *mCreds;
};

class SecureTransportClient : public SecureTransport
{
public:
	class Anonymous : public Credentials
	{
	public:
		Anonymous(void);
		~Anonymous(void);
		
	protected:
		void install(gnutls_session_t session);
		gnutls_anon_client_credentials_t mCreds;
	};

	class PrivateSharedKey : public Credentials
        {
        public:
                PrivateSharedKey(const String &name, const BinaryString &key);
                ~PrivateSharedKey(void);
		
	protected:
		void install(gnutls_session_t session);
                gnutls_psk_client_credentials_t mCreds;
        };	

	class Certificate : public Credentials
        {
        public:
                Certificate(const String &filename);
                ~Certificate(void);
		
	protected:
		void install(gnutls_session_t session);
                gnutls_certificate_credentials_t mCreds;
        };

	SecureTransportClient(Stream *stream, Credentials *creds);	// stream and creds will be deleted
	~SecureTransportClient(void);
};

class SecureTransportServer : public SecureTransport
{
public:
	class Anonymous : public Credentials
	{
	public:
		Anonymous(void);
		~Anonymous(void);
		
	protected:
		void install(gnutls_session_t session);
		gnutls_anon_server_credentials_t mCreds;
	};

	class PrivateSharedKey : public Credentials
        {
        public:
                PrivateSharedKey(void);
                ~PrivateSharedKey(void);

		// Callback to fetch key given username
		virtual bool callback(const String &username, BinaryString &key) = 0;
		
	protected:
		// Mapping to retrieve PrivateSharedKey from static callback
		static Map<gnutls_session_t, PrivateSharedKey*> CredsMap;
		static Map<PrivateSharedKey*, gnutls_session_t> CredsMapReverse;
		static Mutex CredsMapMutex;
		static int CredsCallback(gnutls_session_t session, const char* username, gnutls_datum_t* datum); 
		
		void install(gnutls_session_t session);
                gnutls_psk_server_credentials_t mCreds;
        };	

	// TODO: server certificate credentials
	
	SecureTransportServer(Stream *stream, Credentials *creds);	// stream and creds will be deleted
	~SecureTransportServer(void);
};

}

#endif
