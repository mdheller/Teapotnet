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

#ifndef TPOT_MAP_H
#define TPOT_MAP_H

#include "include.h"
#include "exception.h"
#include "serializable.h"

#include <map>

namespace tpot
{

template<typename K, typename V>
class Map : public std::map<K,V>
{
public:
	void insert(const K &key, const V &value);
	bool contains(const K &key) const;
	bool get(const K &key, V &value) const;
	const V &get(const K &key) const;
	V &get(const K &key);
};

template<typename K, typename V>
class SerializableMap : public Map<K,V>, public Serializable
{
	void serialize(Serializer &s) const;
	bool deserialize(Serializer &s);
	
	class SerializablePair : public Serializer::Pair
	{
	public:
		K key;
		V value;
	  
		SerializablePair(void);
		SerializablePair(const K &key, const V &value);
		 
		void serializeKey(Serializer &s) const;
		void serializeValue(Serializer &s) const;
		bool deserializeKey(Serializer &s);
		bool deserializeValue(Serializer &s);
	};
};

typedef SerializableMap<String,String> StringMap;

template<typename K, typename V>
void Map<K,V>::insert(const K &key, const V &value)
{
	(*this)[key] = value;
}

template<typename K, typename V>
bool Map<K,V>::contains(const K &key) const
{
	typename std::map<K,V>::const_iterator it = this->find(key);
	return (it != this->end());
}

template<typename K, typename V>
bool Map<K,V>::get(const K &key, V &value) const
{
	typename std::map<K,V>::const_iterator it = this->find(key);
	if(it == this->end()) return false;
	value = it->second;
	return true;
}

template<typename K, typename V>
const V &Map<K,V>::get(const K &key) const
{
	typename std::map<K,V>::const_iterator it = this->find(key);
	if(it == this->end()) throw OutOfBounds("Map key does not exist");
	return it->second;
}

template<typename K, typename V>
V &Map<K,V>::get(const K &key)
{
	typename std::map<K,V>::iterator it = this->find(key);
	if(it == this->end()) throw OutOfBounds("Map key does not exist");
	return it->second;
}

template<typename K, typename V>
void SerializableMap<K,V>::serialize(Serializer &s) const
{
	s.outputMapBegin(uint32_t(this->size()));

	for(	typename std::map<K,V>::const_iterator it = this->begin();
				it != this->end();
				++it)
	{
		SerializablePair pair(it->first, it->second);
		s.output(pair);
	}
	
	s.outputMapEnd();
}

template<typename K, typename V>
bool SerializableMap<K,V>::deserialize(Serializer &s)
{
	this->clear();
	if(!s.inputMapBegin()) return false;

	try {
		while(s.inputMapElement())
		{
			SerializablePair pair;
			AssertIO(s.input(pair));
			this->insert(pair.key, pair.value);
		}
	}
	catch(const Serializer::End &end)
	{
	  
	}
	
	return true;
}

template<typename K, typename V>
SerializableMap<K,V>::SerializablePair::SerializablePair(void)
{
  
}

template<typename K, typename V>
SerializableMap<K,V>::SerializablePair::SerializablePair(const K &key, const V &value) :
	key(key),
	value(value)
{
	  
}

template<typename K, typename V>
void SerializableMap<K,V>::SerializablePair::serializeKey(Serializer &s) const
{
	s.output(key);  
}

template<typename K, typename V>
void SerializableMap<K,V>::SerializablePair::serializeValue(Serializer &s) const
{
	s.output(value);
}

template<typename K, typename V>
bool SerializableMap<K,V>::SerializablePair::deserializeKey(Serializer &s)
{
	s.input(key);
}

template<typename K, typename V>
bool SerializableMap<K,V>::SerializablePair::deserializeValue(Serializer &s)
{
	s.input(value);
}

}

#endif
