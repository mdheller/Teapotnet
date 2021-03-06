/*************************************************************************
 *   Copyright (C) 2011-2016 by Paul-Louis Ageneau                       *
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

#ifndef TPN_USER_H
#define TPN_USER_H

#include "tpn/include.hpp"
#include "tpn/interface.hpp"
#include "tpn/indexer.hpp"
#include "tpn/board.hpp"

#include "pla/serializable.hpp"
#include "pla/securetransport.hpp"
#include "pla/crypto.hpp"
#include "pla/alarm.hpp"
#include "pla/map.hpp"

namespace tpn
{

class AddressBook;

class User : public Serializable, public HttpInterfaceable
{
public:
	static unsigned Count(void);
	static void GetNames(Array<String> &array);
	static bool Exist(const String &name);
	static void Register(sptr<User> user);
	static sptr<User> Get(const String &name);
	static sptr<User> GetByIdentifier(const Identifier &id);
	static sptr<User> Authenticate(const String &name, const String &password);

	User(const String &name, const String &password = "");
	virtual ~User(void);

	bool load(void);
	void save(void) const;
	bool recv(const String &password);
	void send(const String &password = "") const;
	bool authenticate(const String &name, const String &password) const;

  void generateKeyPair(void);

	String name(void) const;
	String profilePath(void) const;
	String fileName(void) const;
	String urlPrefix(void) const;
	BinaryString secret(void) const;

	sptr<AddressBook> addressBook(void) const;
	sptr<Board> board(void) const;
	sptr<Indexer> indexer(void) const;

	void invite(const Identifier &remote, const String &name);
	void mergeBoard(sptr<Board> board);
	void unmergeBoard(sptr<Board> board);

	bool isOnline(void) const;
	void setOnline(void);
	void setOffline(void);

	BinaryString getSecretKey(const String &action) const;

	String generateToken(const String &action = "") const;
	bool checkToken(const String &token, const String &action = "") const;

	Identifier identifier(void) const;
	Rsa::PublicKey publicKey(void) const;
	Rsa::PrivateKey privateKey(void) const;
	sptr<SecureTransport::Certificate> certificate(void) const;

	void http(const String &prefix, Http::Request &request);

	void serialize(Serializer &s) const;
	bool deserialize(Serializer &s);
	bool isInlineSerializable(void) const;

private:
	void setKeyPair(const Rsa::PublicKey &pub, const Rsa::PrivateKey &priv);	// calls save()
	void setSecret(const BinaryString &secret);

	String mName;
	String mFileName;
	BinaryString mAuthDigest;
	sptr<AddressBook> mAddressBook;
	sptr<Board> mBoard;
	sptr<Indexer> mIndexer;

	Identifier mIdentifier;
	Rsa::PublicKey	mPublicKey;
	Rsa::PrivateKey	mPrivateKey;
	sptr<SecureTransport::Certificate> mCertificate;
	BinaryString mSecret;

	bool mOnline;
	Alarm mOfflineAlarm;

	BinaryString mTokenSecret;
	mutable Map<String, BinaryString> mSecretKeysCache;

	mutable std::mutex mMutex;

	static Map<String, sptr<User> >	UsersByName;
	static Map<Identifier, String>	UsersByIdentifier;
	static std::mutex		UsersMutex;
};

}

#endif
