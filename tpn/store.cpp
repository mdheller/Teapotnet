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

#include "tpn/store.h"
#include "tpn/user.h"
#include "tpn/directory.h"
#include "tpn/html.h"
#include "tpn/crypto.h"
#include "tpn/random.h"
#include "tpn/lineserializer.h"
#include "tpn/jsonserializer.h"
#include "tpn/config.h"
#include "tpn/time.h"
#include "tpn/mime.h"

namespace tpn
{

Store *Store::Instance = NULL;

Store::Store(void)
{
	mDatabase = new Database("store.db");
	
	mDatabase->execute("CREATE TABLE IF NOT EXISTS blocks\
		(id INTEGER PRIMARY KEY AUTOINCREMENT,\
		digest BLOB,\
		file_id INTEGER,\
		offset INTEGER(8),\
		size INTEGER(8)");
	mDatabase->execute("CREATE INDEX IF NOT EXISTS digest ON blocks (digest)");
	mDatabase->execute("CREATE INDEX IF NOT EXISTS file_id ON blocks (file_id)");
	
	mDatabase->execute("CREATE TABLE IF NOT EXISTS files\
		(id INTEGER PRIMARY KEY AUTOINCREMENT,\
		name TEXT UNIQUE");
	mDatabase->execute("CREATE INDEX IF NOT EXISTS name ON files (name)");
}

Store::~Store(void)
{

}

bool Store::get(const BinaryString &digest, Resource &resource)
{
	Synchonize(this);
	
	// TODO
}

void Store::waitBlock(const BinaryString &digest)
{
	Synchronize(this);
	
	while(true)
	{
		Database::Statement statement = mDatabase->prepare("SELECT 1 FROM blocks WHERE digest = ?1");
		statement.bind(1, digest);
		if(statement.step())
		{
			statement.finalize();
			return;
		}
		
		statement.finalize();
		
		wait();
	}
}

File *Store::getBlock(const BinaryString &digest, int64_t &size)
{
	Synchronize(this);
  
	Database::Statement statement = mDatabase->prepare("SELECT f.name, b.offset, b.size FROM blocks b LEFT JOIN files f ON f.id = b.file_id WHERE b.digest = ?1 LIMIT 1");
	statement.bind(1, digest);
	if(statement.step())
	{
		String filename;
		int64_t offset;
		statement.value(0, filename);
		statement.value(1, offset);
		statement.value(2, size);
		statement.finalize();

		try {		
			File *file = new File(filename);
			file->seekRead(offset);
			return file;
		}
		catch(...)
		{
			notifyFileErasure(filename);
		}
		
		return NULL;
	}
	
	statement.finalize();
	return NULL;
}

void Store::notifyBlock(const BinaryString &digest, const String &filename, int64_t offset, int64_t size)
{
	Synchonize(this);
	
	Database::Statement statement = mDatabase->prepare("INSERT OR IGNORE INTO files (name) VALUES (?1)");
	statement.bind(1, filename);
	statement.execute();
	
	Database::Statement statement = mDatabase->prepare("INSERT OR IGNORE INTO blocks (file_id, offset, size) VALUES ((SELECT id FROM files WHERE name = ?1 LIMIT 1), ?2, ?3)");
	statement.bind(1, filename);
	statement.bind(2, offset);
	statement.bind(3, size);
	statement.execute();
	
	notifyAll();
}

void Store::notifyFileErasure(const String &filename)
{
	Synchonize(this);
	
	Database::Statement statement = mDatabase->prepare("DELETE FROM blocks WHERE file_id = (SELECT id FROM files WHERE name = ?1)");
	statement.bind(1, filename);
	statement.execute();
	
	Database::Statement statement = mDatabase->prepare("DELETE FROM files WHERE name = ?1");
	statement.bind(1, filename);
	statement.execute();
}

}
