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

#include "tracker.h"

namespace tpot
{

const double Tracker::EntryLife = 3600.;	// seconds
  
Tracker::Tracker(int port) :
		Http::Server(port)
{
	mStorage.cleaner   = mStorage.map.begin();
	mAlternate.cleaner = mAlternate.map.begin();
}

Tracker::~Tracker(void)
{

}

void Tracker::process(Http::Request &request)
{
	Synchronize(this);
	//Log("Tracker", "URL " + request.url);	

	if(!request.url[0] == '/') throw 404;
	request.url.ignore();
	
	List<String> list;
	request.url.explode(list, '/');
	if(list.size() != 2 && list.size() != 3) throw 404;
	
	bool alternate = false;
	if(list.size() == 3)
	{
		if(list.back() == "alternate") alternate = true;
	  	if(!list.back().empty()) throw 404;
		list.pop_back();
	}

	if(list.front() != "tracker") throw 404;
	list.pop_front();
	
	try {
		Identifier identifier;
		list.front().extract(identifier);

		if(identifier.size() != 64) throw Exception("Invalid indentifier size");
		
		if(request.method == "POST")
		{
			String port;
			if(request.post.get("port", port))
			{
				String host;
				if(!request.post.get("host", host))
				{
					if(request.headers.contains("X-Forwarded-For")) 
						host = request.headers["X-Forwarded-For"];
					else host = request.sock->getRemoteAddress().host();
				}
				
				Address addr(host, port);
				insert(mStorage, identifier, addr);
				//Log("Tracker", "POST " + identifier.toString() + " -> " + addr.toString());
			}
			
			String addresses;
			if(request.post.get("addresses", addresses))
			{
				List<String> list;
				addresses.explode(list, ',');
				
				for(	List<String>::iterator it = list.begin();
					it != list.end();
					++it)
				try {
				      Address addr(*it);
				      if(alternate) insert(mAlternate, identifier, addr);
				      else insert(mStorage, identifier, addr);
				      //Log("Tracker", "POST " + identifier.toString() + " -> " + addr.toString());
				}
				catch(...)
				{
				  
				}
			}

			if(!alternate && request.post.get("alternate", addresses))
			{
				List<String> list;
				addresses.explode(list, ',');
				
				for(	List<String>::iterator it = list.begin();
					it != list.end();
					++it)
				try {
				      Address addr(*it);
				      insert(mAlternate, identifier, addr);
				      //Log("Tracker", "POST " + identifier.toString() + " -> " + addr.toString() + " (alternate)");
				}
				catch(...)
				{
				  
				}
			}
			
			Http::Response response(request,200);
			response.send();
		}
		else {
			SerializableArray<Address> addrs;
			if(alternate) retrieve(mAlternate, identifier, addrs);
			else retrieve(mStorage, identifier, addrs);
			if(addrs.empty()) throw 404;

			//Log("Tracker", "GET " + identifier.toString());

			Http::Response response(request,200);
			response.headers["Content-Type"] = "text/plain";
			response.send();
			response.sock->write(addrs);
		}
	}
	catch(int code)
	{
		Http::Response response(request,code);
                response.send();
	}
	catch(const Exception &e)
	{
		Log("Tracker", String("Error: ") + e.what());
		Http::Response response(request,400);
                response.send();
	}
}

void Tracker::insert(Tracker::Storage &s, const Identifier &identifier, const Address &addr)
{
	int nbr = 1;
	if(nbr > s.map.size()) nbr = s.map.size();
	for(int i=0; i<nbr; ++i)
	{
	  	if(s.cleaner == s.map.end()) s.cleaner = s.map.begin();

		Map<Address,Time> &submap = s.cleaner->second;
		Map<Address,Time>::iterator it = submap.begin();
		while(it != submap.end())
		{
			if(Time::Now() - it->second >= EntryLife) submap.erase(it++);
			else it++;
		} 
			
		if(submap.empty()) s.map.erase(s.cleaner++);
		else s.cleaner++;	
	}
	
	Map<Address,Time> &submap = s.map[identifier];
	submap[addr] = Time::Now();
}

void Tracker::retrieve(Tracker::Storage &s, const Identifier &identifier, Array<Address> &array) const
{
	array.clear();

	map_t::const_iterator it = s.map.find(identifier);
	if(it == s.map.end()) return;

	const Map<Address,Time> &submap = it->second;
	if(submap.empty()) return;

	array.reserve(submap.size());
	for(	Map<Address,Time>::const_iterator it = submap.begin();
		it != submap.end();
		++it)
	{
		array.push_back(it->first);
	}

	std::random_shuffle(array.begin(), array.end());
}

}
