/*************************************************************************
 *   Copyright (C) 2011-2014 by Paul-Louis Ageneau                       *
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

#ifndef PLA_SECURETRANSPORT_H
#define PLA_SECURETRANSPORT_H

#include "pla/include.h"
#include "pla/stream.h"
#include "pla/string.h"
#include "pla/list.h"
#include "pla/crypto.h"
#include "pla/serversocket.h"
#include "pla/datagramsocket.h"

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

namespace pla
{
	
class SecureTransport : public Stream
{
public:
	static void Init(void);
	static void Cleanup(void);
	static void GenerateParams(void);
	
	class Credentials
	{
	public:
		Credentials(void) {}
		virtual ~Credentials(void) {}
		void install(SecureTransport *st);
		
	protected:
		virtual void install(gnutls_session_t session, String &priorities) = 0;
	}; 
	
	class Certificate : public Credentials
	{
	public:
		Certificate(void);
		Certificate(const String &certFilename, const String &keyFilename);	// PEM encoded
		~Certificate(void);
		
	protected:
		void install(gnutls_session_t session, String &priorities);
                gnutls_certificate_credentials_t mCreds;
        };

	class RsaCertificate : public Certificate
	{
	public:
		RsaCertificate(const Rsa::PublicKey &pub, const Rsa::PrivateKey &priv, const String &name);
		~RsaCertificate(void);

	protected:
                gnutls_x509_crt_t mCrt;
                gnutls_x509_privkey_t mKey;
	};
	
	virtual ~SecureTransport(void);
	
	void addCredentials(Credentials *creds, bool mustDelete = false);	// creds will be deleted if mustDelete == true
	void handshake(void);
	void close(void);
	
	void setHostname(const String &hostname);	// remote hostname for client
	
	virtual bool isClient(void);
	bool isHandshakeDone(void);
	bool isAnonymous(void);
	bool hasPrivateSharedKey(void);
	bool hasCertificate(void);
	
	size_t readData(char *buffer, size_t size); 
	void writeData(const char *data, size_t size);
	// TODO: waitData
	
	struct Verifier
        {
		virtual bool verifyCertificate(const Rsa::PublicKey &pub) { return false; }
		virtual bool verifyPublicKey(const Rsa::PublicKey &pub) { return false; }
		virtual bool verifyPrivateSharedKey(const String &username, BinaryString &key) { return false; }
		virtual bool verifyName(const String &name, SecureTransport *transport) { return true; }	// default is true
        };
	
	void setVerifier(Verifier *verifier);
	
protected:
	static ssize_t	DirectWriteCallback(gnutls_transport_ptr_t ptr, const void* data, size_t len);
	static ssize_t	WriteCallback(gnutls_transport_ptr_t ptr, const void* data, size_t len);
	static ssize_t	ReadCallback(gnutls_transport_ptr_t ptr, void* data, size_t maxlen);
	static int	TimeoutCallback(gnutls_transport_ptr_t ptr, unsigned int ms);
	
	static int CertificateCallback(gnutls_session_t session);
	static int PrivateSharedKeyCallback(gnutls_session_t session, const char* username, gnutls_datum_t* datum); 
	
	static const String DefaultPriorities;
	static gnutls_dh_params_t Params;
	static Mutex ParamsMutex;
	
	SecureTransport(Stream *stream, bool server, bool datagram);	// stream will be deleted on success
	
	gnutls_session_t mSession;
	Stream *mStream;
	Verifier *mVerifier;
	String mPriorities;
	String mHostname;
	
	List<Credentials*> mCredsToDelete;
	bool mIsHandshakeDone;
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
		void install(gnutls_session_t session, String &priorities);
		gnutls_anon_client_credentials_t mCreds;
	};

	class PrivateSharedKey : public Credentials
        {
        public:
                PrivateSharedKey(const String &name, const BinaryString &key);
                ~PrivateSharedKey(void);
	
	protected:
		void install(gnutls_session_t session, String &priorities);
                gnutls_psk_client_credentials_t mCreds;
        };

	SecureTransportClient(Stream *stream, Credentials *creds = NULL, const String &hostname = "", bool datagram = false);	// creds will be deleted
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
		void install(gnutls_session_t session, String &priorities);
		gnutls_anon_server_credentials_t mCreds;
	};

	class PrivateSharedKey : public Credentials
	{
	public:
		PrivateSharedKey(void);
		~PrivateSharedKey(void);
		
	protected:
		void install(gnutls_session_t session, String &priorities);
		gnutls_psk_server_credentials_t mCreds;
	};	
	
	// These functions are preferred, especially for datagrams (protection against DoS)
	static SecureTransport *Listen(ServerSocket &sock, bool requestClientCertificate = false);
	static SecureTransport *Listen(DatagramSocket &sock, bool requestClientCertificate = false);
	
	SecureTransportServer(Stream *stream, Credentials *creds = NULL, bool requestClientCertificate = false, bool datagram = false);	// creds will be deleted
	~SecureTransportServer(void);
	
	bool isClient(void);
	
protected:
	static int PostClientHelloCallback(gnutls_session_t session);
};

}

#endif