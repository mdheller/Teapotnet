/*************************************************************************
 *   Copyright (C) 2011-2017 by Paul-Louis Ageneau                       *
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

#ifndef TPN_BOARD_H
#define TPN_BOARD_H

#include "tpn/include.hpp"
#include "tpn/mail.hpp"
#include "tpn/network.hpp"
#include "tpn/interface.hpp"

#include "pla/binarystring.hpp"
#include "pla/string.hpp"
#include "pla/array.hpp"
#include "pla/map.hpp"
#include "pla/set.hpp"

namespace tpn
{

class Board : public Network::Publisher, public Network::Subscriber, public HttpInterfaceable
{
public:
	Board(const String &name, const String &secret = "", const String &displayName = "");
	~Board(void);

	String urlPrefix(void) const;
	bool hasNew(void) const;
	int  unread(void) const;

	void addSubBoard(sptr<Board> board);
	void removeSubBoard(sptr<Board> board);

	bool post(const Mail &mail);

	// Publisher
	bool anounce(const Network::Locator &locator, List<BinaryString> &targets);

	// Subscriber
	bool incoming(const Network::Locator &locator, const BinaryString &target);
	bool incoming(const Network::Locator &locator, const Mail &mail);

	// HttpInterfaceable
	void http(const String &prefix, Http::Request &request);

private:
	void add(const List<Mail> &mails);	// locks
	void appendMail(const Mail &mail);	// mutex must be locked first

	String mName;
	String mDisplayName;
	String mSecret;
	Set<BinaryString> mDigests, mPreviousDigests, mProcessedDigests;

	Map<BinaryString, Mail> mMails;
	Map<BinaryString, List<const Mail*> > mOrphans;
	Array<const Mail*> mListing;

	Set<sptr<Board> > mSubBoards;
	Set<Board*> mBoards;

	mutable std::mutex mMutex;
	mutable std::condition_variable mCondition;
	mutable bool mHasNew;
	mutable unsigned mUnread;
};

}

#endif
