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

#include "tpn/request.h"
#include "tpn/config.h"

#include "pla/jsonserializer.h"
#include "pla/mime.h"

namespace tpn
{

Request::Request(Resource &resource) :
	mListDirectories(true),
	mFinished(false)
{
	mUrlPrefix = "/request/" + String::random(32);
	Interface::Instance->add(mUrlPrefix, this);
	
	addResult(resource);
}
  
Request::Request(const String &target, bool listDirectories) :
	mListDirectories(listDirectories),
	mFinished(false)
{
	mUrlPrefix = "/request/" + String::random(32);
	Interface::Instance->add(mUrlPrefix, this);
	
	subscribe(target);
}
  
Request::Request(const String &target, const Identifier &peer, bool listDirectories) :
	Subscriber(peer),
	mListDirectories(listDirectories),
	mFinished(false)
{
	mUrlPrefix = "/request/" + String::random(32);
	Interface::Instance->add(mUrlPrefix, this);
	
	subscribe(target);
}

Request::~Request(void)
{
	//LogDebug("Request", "Deleting request: " + mUrlPrefix);
	Interface::Instance->remove(mUrlPrefix, this);
	
	// TODO: wait for http requests to finish
	// TODO: wait for threads
	
	// unsubscribe is automatic
}

String Request::urlPrefix(void) const
{
	Synchronize(this);
	return mUrlPrefix;
}

int Request::resultsCount(void) const
{
	Synchronize(this);
	return int(mResults.size());
}

void Request::addResult(Resource &resource)
{
	Synchronize(this);
	
	if(resource.isDirectory() && mListDirectories)
	{
		Desynchronize(this);
		
		LogDebug("Request", "Listing directory: " + resource.digest().toString());
		
		// TODO: thread
		// List directory and add records
		Resource::Reader reader(&resource);
		Resource::DirectoryRecord record;
		while(reader.readDirectory(record))
		{
			Synchronize(this);
			mResults.append(record);
			mDigests.insert(record.digest);
		}
		
		SynchronizeStatement(this, mFinished = true);
		notifyAll();
	}
	else {
		// Do not list, just add corresponding record
		 addResult(resource.getDirectoryRecord());
	}
}

void Request::addResult(const Resource::DirectoryRecord &record)
{
	Synchronize(this);
	if(!mDigests.contains(record.digest))
	{
		LogDebug("Request", "Adding result: " + record.digest.toString());
		
		mResults.append(record);
		mDigests.insert(record.digest);
		notifyAll();
	}
}

void Request::getResult(int i, Resource::DirectoryRecord &record) const
{
	Synchronize(this);
	Assert(i < resultsCount());
	record = mResults.at(i);
}

void Request::setAutoDelete(double timeout)
{
	// TODO
}

void Request::http(const String &prefix, Http::Request &request)
{
	Synchronize(this);
	
	int next = 0;
	if(request.get.contains("next"))
		request.get["next"].extract(next);
	
	double timeout = 60.;
	if(request.get.contains("timeout"))
		request.get["timeout"].extract(timeout);
	
	while(next >= int(mResults.size()) && !mFinished)
	{
		if(!wait(timeout))
			break;
	}
	
	if(request.get.contains("playlist"))
	{
		// Playlist
		
		Http::Response response(request, 200);
		response.headers["Content-Disposition"] = "attachment; filename=\"playlist.m3u\"";
		response.headers["Content-Type"] = "audio/x-mpegurl";
		response.send();
					
		String host;
		request.headers.get("Host", host);
		createPlaylist(response.stream, host);
	}
	else {
		// JSON
		
		Http::Response response(request, 200);
		response.headers["Content-Type"] = "application/json";
		response.send();
		
		JsonSerializer json(response.stream);
		json.outputArrayBegin();
		for(int i = next; i < int(mResults.size()); ++i)
			json.outputArrayElement(mResults[i]);
		json.outputArrayEnd();
	}
}

bool Request::incoming(const Identifier &peer, const String &prefix, const String &path, const BinaryString &target)
{
	Synchronize(this);
  
	if(mDigests.contains(target)) return true;
	mDigests.insert(target);

	if(fetch(peer, prefix, path, target))
	{
		Resource resource(target, true);	// local only (already fetched)
		addResult(resource);
	}
	
	return true;
}

void Request::createPlaylist(Stream *output, String host)
{
	Synchronize(this);
	Assert(output);
	
	if(host.empty()) 
		host = String("localhost:") + Config::Get("interface_port");
	
	output->writeLine("#EXTM3U");
	for(int i = 0; i < int(mResults.size()); ++i)
	{
		const Resource::DirectoryRecord &record = mResults[i];
		if(record.type == "directory" || record.digest.empty()) continue;
		if(!Mime::IsAudio(record.name) && !Mime::IsVideo(record.name)) continue;
		String link = "http://" + host + "/file/" + record.digest.toString();
		output->writeLine("#EXTINF:-1," + record.name.beforeLast('.'));
		output->writeLine(link);
	}
}

}
