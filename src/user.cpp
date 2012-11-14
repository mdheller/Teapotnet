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

#include "user.h"
#include "config.h"
#include "file.h"
#include "directory.h"
#include "sha512.h"
#include "html.h"

namespace tpot
{

Map<String, User*>	User::UsersByName;
Map<Identifier, User*>	User::UsersByAuth;
Mutex			User::UsersMutex;
  
unsigned User::Count(void)
{
	 UsersMutex.lock();
	 unsigned count = UsersByName.size();
	 UsersMutex.unlock();
	 return count;
}

bool User::Exist(const String &name)
{
	return (User::Get(name) != NULL);
}

User *User::Get(const String &name)
{
	User *user = NULL;
	UsersMutex.lock();
	if(UsersByName.get(name, user)) 
	{
	  	UsersMutex.unlock();
		return user;
	}
	UsersMutex.unlock();
	return NULL; 
}

User *User::Authenticate(const String &name, const String &password)
{
	Identifier hash;
	Sha512::Hash(name + ':' + password, hash, Sha512::CryptRounds);
	
	User *user = NULL;
	UsersMutex.lock();
	if(UsersByAuth.get(hash, user)) 
	{
	  	UsersMutex.unlock();
		return user;
	}
	UsersMutex.unlock();
	Log("User::Authenticate", "Authentication failed for \""+name+"\"");
	return NULL;
}

User::User(const String &name, const String &password) :
	mName(name),
	mAddressBook(new AddressBook(this)),
	mStore(new Store(this))
{
	if(password.empty())
	{
		File file(profilePath()+"password", File::Read);
		file.read(mHash);
		file.close();
	}
	else {
		Sha512::Hash(name + ':' + password, mHash, Sha512::CryptRounds);
		
		File file(profilePath()+"password", File::Write);
		file.write(mHash);
		file.close();
	}
	
	UsersMutex.lock();
	UsersByName.insert(mName, this);
	UsersByAuth.insert(mHash, this);
	UsersMutex.unlock();
	
	Interface::Instance->add("/"+mName, this);
}

User::~User(void)
{
  	UsersMutex.lock();
	UsersByName.erase(mName);
  	UsersByAuth.erase(mHash);
	UsersMutex.unlock();
	
	Interface::Instance->remove("/"+mName);
	
	delete mAddressBook;
	delete mStore;
}

const String &User::name(void) const
{
	return mName; 
}

String User::profilePath(void) const
{
	if(!Directory::Exist(Config::Get("profiles_dir"))) Directory::Create(Config::Get("profiles_dir"));
	String path = Config::Get("profiles_dir") + Directory::Separator + mName;
	if(!Directory::Exist(path)) Directory::Create(path);
	return path + Directory::Separator;
}

AddressBook *User::addressBook(void) const
{
	return mAddressBook;
}

Store *User::store(void) const
{
	return mStore;
}

void User::http(const String &prefix, Http::Request &request)
{
	Synchronize(this);
	
	try {
		String url = request.url;
		
		if(url.empty() || url == "/")
		{
			Http::Response response(request,200);
			response.send();
			
			Html page(response.sock);
			page.header(String("Welcome, ")+mName+" !");

			page.open("div",".menu");
			
			page.openForm(prefix + "/search", "post", "searchform");
			page.input("text","query");
			page.button("search","Search");
			page.closeForm();
			page.br();
			page.br();
			
			page.link(prefix+"/contacts/","Contacts");
			int msgcount = mAddressBook->unreadMessagesCount();
			if(msgcount)
			{
				page.space();
				page.span(String("[")+String::number(msgcount)+String(" new messages]"), ".important");
			}
			page.br();
			page.link(prefix+"/files/","Files");
			page.br();
			page.close("div");
			
			page.footer();
			return;
		}
		
		if(url == "/search" || url == "/search/")
		{
			String query;
			if(request.post.contains("query"))
			{
				query = request.post.get("query");
				query.trim();
			}
				
			Http::Response response(request,200);
			response.send();
				
			Html page(response.sock);
			page.header("Search");
				
			page.openForm(prefix + "/search", "post", "searchform");
			page.input("text","query",query);
			page.button("search","Search");
			page.closeForm();
			page.br();
				
			if(query.empty())
			{
				page.footer();
				return;
			}
			
			Request trequest("search:"+query, false);	// no data
			trequest.submit();
			
			const unsigned timeout = Config::Get("request_timeout").toInt();
				
			{
				Desynchronize(this);
				trequest.lock();
				trequest.wait(timeout);
			}
			
			try {
				page.open("div",".box");
				page.open("table",".files");
				for(int i=0; i<trequest.responsesCount(); ++i)
				{
					Request::Response *tresponse = trequest.response(i);
					if(tresponse->error()) continue;
					
					// Check contact
					const AddressBook::Contact *contact = mAddressBook->getContact(tresponse->peering());
					if(!contact) continue;
					
					// Check info
					StringMap map = tresponse->parameters();
					if(!map.contains("type")) continue;
					if(!map.contains("path")) continue;
					if(map.get("type") != "directory" && !map.contains("hash")) continue;
					if(!map.contains("name")) map["name"] = map["path"].afterLast('/');
					
					page.open("tr");
					page.open("td");
					page.text("("); page.link(contact->urlPrefix()+"/", contact->name()); page.text(")");
					page.close("td");
					page.open("td"); 
					if(map.get("type") == "directory") page.link(contact->urlPrefix() + "/files" + map.get("path"), map.get("name"));
					else page.link("/" + map.get("hash"), map.get("name"));
					page.close("td");
					page.open("td"); 
					if(map.get("type") == "directory") page.text("directory");
					else if(map.contains("size")) page.text(String::hrSize(map.get("size")));
					page.close("td");
					page.close("tr");
				}
				page.close("table");
				page.close("div");
			}
			catch(const Exception &e)
			{
				Log("User::http", String("Unable to list files: ") + e.what());
				page.close("table");
				page.close("div");
				page.text("Error, unable to list files");
			}
				
			trequest.unlock();
			page.footer();
			return;
		}
	}
	catch(const Exception &e)
	{
		Log("User::http",e.what());
		throw 404;	// Httpd handles integer exceptions
	}
			
	throw 404;
}

void User::run(void)
{
	while(true)
	{
		wait(5*60*1000);
		if(!mAddressBook->isRunning()) mAddressBook->start();
		if(!mStore->isRunning()) mStore->start();
	}
}

}
