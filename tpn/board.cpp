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

#include "tpn/board.h"
#include "tpn/resource.h"
#include "tpn/cache.h"
#include "tpn/html.h"

#include "pla/jsonserializer.h"
#include "pla/binaryserializer.h"

namespace tpn
{

Board::Board(const String &name, const String &displayName) :
	mName(name),
	mDisplayName(displayName),
	mHasNew(false)
{
	Assert(!mName.empty() && mName[0] == '/');	// TODO

	Interface::Instance->add("/mail" + mName, this);
	
	String prefix = "/mail" + mName;
	
	BinaryString digest;
	Cache::Instance->retrieveMapping(prefix, digest);
	
	if(!digest.empty())
		if(fetch(prefix, "/", digest))
			incoming(prefix, "/", digest);
	
	publish(prefix);
	subscribe(prefix);
}

Board::~Board(void)
{
	Interface::Instance->remove("/mail" + mName, this);
	
	String prefix = "/mail" + mName;
	publish(prefix);
	subscribe(prefix);
}

bool Board::hasNew(void) const
{
	Synchronize(this);

	bool value = false;
	std::swap(mHasNew, value);
	return value;
}

bool Board::add(Mail &mail)
{
	Synchronize(this);
	
	if(mMails.contains(mail))
		return false;
	
	const Mail *p = &*mMails.insert(mail).first;
	mUnorderedMails.append(p);
	
	mDigest.clear();
	publish("/mail" + mName);	// calls digest()
	notifyAll();
	return true;
}

BinaryString Board::digest(void) const
{
	if(mDigest.empty())
	{
		String tempFileName = File::TempName();
		File tempFile(tempFileName, File::Truncate);
		
		BinarySerializer serializer(&tempFile);
		for(Set<Mail>::const_iterator it = mMails.begin();
			it != mMails.end();
			++it)
		{
			serializer.write(*it);
		}
		
		tempFile.close();
		
		Resource resource;
		resource.process(Cache::Instance->move(tempFileName), mName, "mail");
		
		mDigest = resource.digest();
		
		Cache::Instance->storeMapping("/mail" + mName, mDigest);
	}
  
	return mDigest;
}

bool Board::anounce(const Identifier &peer, const String &prefix, const String &path, BinaryString &target)
{
	Synchronize(this);
	
	target = digest();
	return true;
}
	
bool Board::incoming(const String &prefix, const String &path, const BinaryString &target)
{
	Synchronize(this);
	
	if(target == digest())
		return false;
	
	if(fetch(prefix, path, target))
	{
		Resource resource(target, true);	// local only (already fetched)
		if(resource.type() != "mail")
			return false;
		
		Resource::Reader reader(&resource);
		BinarySerializer serializer(&reader);
		Mail mail;
		while(serializer.read(mail))
			if(!mMails.contains(mail))
			{
				const Mail *p = &*mMails.insert(mail).first;
				mUnorderedMails.append(p);
			}
		
		mDigest.clear();	// so digest must be recomputed
		if(digest() != target)
			publish("/mail" + mName);
		
		notifyAll();
	}
	
	return true;
}

void Board::http(const String &prefix, Http::Request &request)
{
	Synchronize(this);
	Assert(!request.url.empty());
	
	try {
		if(request.url == "/")
		{
			if(request.method == "POST")
			{
				if(request.post.contains("message") && !request.post["message"].empty())
				{
					// Anonymous
					Mail mail;
					mail.setContent(request.post["message"]);
					mail.setAuthor(request.post["author"]);
					
					BinaryString parent;
					if(request.post.contains("parent"))
					{
						request.post["parent"].extract(parent);
						mail.setParent(parent);
					}
					
					add(mail);
					
					Http::Response response(request, 200);
					response.send();
				}
				
				throw 400;
			}
		  
			if(request.get.contains("json"))
			{
				int next = 0;
				if(request.get.contains("next"))
					request.get["next"].extract(next);
				
				double timeout = 60.;
				if(request.get.contains("timeout"))
					request.get["timeout"].extract(timeout);
				
				while(next >= int(mUnorderedMails.size()))
				{
					if(!wait(timeout))
						break;
				}
				
				Http::Response response(request, 200);
				response.headers["Content-Type"] = "application/json";
				response.send();
				
				JsonSerializer json(response.stream);
				json.setOptionalOutputMode(true);
				json.outputArrayBegin();
				for(int i = next; i < int(mUnorderedMails.size()); ++i)
					json.outputArrayElement(*mUnorderedMails[i]);
				json.outputArrayEnd();
				return;
			}
			
			bool isPopup = request.get.contains("popup");
			
			Http::Response response(request, 200);
			response.send();

			Html page(response.stream);
			
			String title = (!mDisplayName.empty() ? mDisplayName : "Board " + mName); 
			page.header(title, isPopup);
			
			page.open("div","topmenu");	
			if(isPopup) page.span(title, ".button");
			//page.raw("<a class=\"button\" href=\"#\" onclick=\"createFileSelector('/"+mUser->name()+"/myself/files/?json', '#fileSelector', 'input.attachment', 'input.attachmentname','"+mUser->generateToken("directory")+"'); return false;\">Send file</a>");
			
			// TODO: should be hidden in CSS
#ifndef ANDROID
			if(!isPopup)
			{
				String popupUrl = Http::AppendGet(request.fullUrl, "popup");
				page.raw("<a class=\"button\" href=\""+popupUrl+"\" target=\"_blank\" onclick=\"return popup('"+popupUrl+"','/');\">Popup</a>");
			}
#endif
			page.close("div");
			
			page.div("", "fileSelector");	
			
			if(isPopup) page.open("div", "board");
			else page.open("div", "board.box");
			
			page.open("div", "mail");
			page.close("div");
			
			page.open("div", ".panel");
			page.div("","attachedfile");
			page.openForm("#", "post", "boardform");
			page.textarea("input");
			page.input("hidden", "attachment");
			page.input("hidden", "attachmentname");
			page.closeForm();
			page.close("div");

			page.close("div");
			
			page.javascript("function post() {\n\
					var message = $(document.boardform.input).val();\n\
					var attachment = $(document.boardform.attachment).val();\n\
					if(!message) return false;\n\
					var fields = {};\n\
					fields['message'] = message;\n\
					if(attachment) fields['attachment'] = attachment;\n\
					$.post('"+prefix+request.url+"', fields)\n\
						.fail(function(jqXHR, textStatus) {\n\
							alert('The message could not be sent.');\n\
						});\n\
					$(document.boardform.input).val('');\n\
					$(document.boardform.attachment).val('');\n\
					$(document.boardform.attachmentname).val('');\n\
					$('#attachedfile').hide();\n\
				}\n\
				$(document.boardform).submit(function() {\n\
					post();\n\
					return false;\n\
				});\n\
				$(document.boardform.attachment).change(function() {\n\
					$('#attachedfile').html('');\n\
					$('#attachedfile').hide();\n\
					var filename = $(document.boardform.attachmentname).val();\n\
					if(filename != '') {\n\
						$('#attachedfile').append('<img class=\"icon\" src=\"/file.png\">');\n\
						$('#attachedfile').append('<span class=\"filename\">'+filename+'</span>');\n\
						$('#attachedfile').show();\n\
					}\n\
					$(document.boardform.input).focus();\n\
					if($(document.boardform.input).val() == '') {\n\
						$(document.boardform.input).val(filename);\n\
						$(document.boardform.input).select();\n\
					}\n\
				});\n\
				$('#attachedfile').hide();\n\
				setMailReceiver('"+Http::AppendGet(request.fullUrl, "json")+"','#mail');");
			
			page.footer();
			return;
		}
	}
	catch(const Exception &e)
	{
		LogWarn("AddressBook::http", e.what());
		throw 500;
	}
	
	throw 404;
}

}
