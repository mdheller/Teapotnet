/*************************************************************************
 *   Copyright (C) 2011-2016 by Paul-Louis Ageneau                       *
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

#ifndef PLA_ALARM_H
#define PLA_ALARM_H

#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>

namespace pla 
{

class Alarm
{
public:
	using clock = std::chrono::steady_clock;
	typedef std::chrono::duration<double> duration;
	typedef std::chrono::time_point<clock, duration> time_point;
	
	Alarm(void);
	template<class F, class... Args> Alarm(F&& f, Args&&... args);
	~Alarm(void);
	
	template<class F, class... Args>
	auto set(F&& f, Args&&... args)
		-> std::future<typename std::result_of<F(Args...)>::type>;
	
	template<class F, class... Args>
	auto schedule(time_point time, F&& f, Args&&... args)
		-> std::future<typename std::result_of<F(Args...)>::type>;
	
	template<class F, class... Args>
	auto schedule(duration d, F&& f, Args&&... args)	
		-> std::future<typename std::result_of<F(Args...)>::type>;
	
	void schedule(time_point time);
	void schedule(duration d);
	void cancel(void);
	void join(void);
	
private:
	std::mutex mutex;
	std::condition_variable condition;
	std::thread thread;
	std::function<void()> function;
	time_point time;
	bool stop;
};

inline Alarm::Alarm(void) : time(time_point::min()), stop(false)
{
	this->thread = std::thread([this]()
	{
		while(true)
		{
			std::unique_lock<std::mutex> lock(mutex);
			
			if(this->time == time_point::min())
			{
				if(this->stop) break;
				this->condition.wait(lock);
			}
			
			if(this->time > clock::now())
			{
				this->condition.wait_until(lock, this->time);
			}
			else {
				this->time = time_point::min();
				if(this->function) 
				{
					std::function<void()> f = this->function;
					lock.unlock();
					f();
				}
			}
		}
	});
}

template<class F, class... Args>
Alarm::Alarm(F&& f, Args&&... args) : Alarm()
{
	set(std::forward<F>(f), std::forward<Args>(args)...);
}

inline Alarm::~Alarm(void)
{
	join();
}

template<class F, class... Args>
auto Alarm::set(F&& f, Args&&... args)
	-> std::future<typename std::result_of<F(Args...)>::type>
{
	using type = typename std::result_of<F(Args...)>::type;

	auto task = std::make_shared<std::packaged_task<type()> >(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
	std::future<type> result = task->get_future();	

	{
		std::unique_lock<std::mutex> lock(mutex);
		this->function = [task]() 
		{ 
			(*task)();
			task->reset();
		};
	}
	
	return result;
}

template<class F, class... Args>
auto Alarm::schedule(time_point time, F&& f, Args&&... args) 
	-> std::future<typename std::result_of<F(Args...)>::type>
{
	using type = typename std::result_of<F(Args...)>::type;

	auto task = std::make_shared<std::packaged_task<type()> >(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
	std::future<type> result = task->get_future();	

	{
		std::unique_lock<std::mutex> lock(mutex);
		if(this->stop) throw std::runtime_error("schedule on stopped Alarm");
		this->time = time;
		this->function = [task]() 
		{
			(*task)();
			task->reset();
		};
	}
	
	condition.notify_all();
	return result;
}


template<class F, class... Args>
auto Alarm::schedule(duration d, F&& f, Args&&... args) 
	-> std::future<typename std::result_of<F(Args...)>::type>
{
	return schedule(clock::now() + d, std::forward<F>(f), std::forward<Args>(args)...);
}

inline void Alarm::schedule(time_point time)
{
	{
		std::unique_lock<std::mutex> lock(mutex);
		if(this->stop) throw std::runtime_error("reschedule on stopped Alarm");
		this->time = time;
	}
	
	condition.notify_all();
}

inline void Alarm::schedule(duration d)
{
	schedule(clock::now() + d);
}

inline void Alarm::cancel(void)
{
	{
		std::unique_lock<std::mutex> lock(mutex);
		this->time = time_point::min();
	}
	
	condition.notify_all();
}

inline void Alarm::join(void)
{
	{
		std::unique_lock<std::mutex> lock(mutex);
		this->stop = true;
	}
	
	condition.notify_all();
	
	if(thread.get_id() == std::this_thread::get_id()) thread.detach();
	else if(thread.joinable()) thread.join();
}

}

#endif
