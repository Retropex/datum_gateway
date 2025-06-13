/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdatomic.h>
#include <jansson.h>
#include <inttypes.h>
#include <curl/curl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_protocol.h"
#include "datum_utils.h"
#include "datum_sockets.h"

int datum_active_threads = 0;
int datum_active_clients = 0;

int get_remote_ip(T_DATUM_CLIENT_DATA *client, char *ip, size_t max_len) {
	if (datum_config.stratum_v1_trust_proxy) {
		strncpy(ip, client->rem_host, max_len-1);
		ip[max_len-1] = 0;
		return 0;
	}
	int fd = client->fd;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	
	// Get the address of the peer
	if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == -1) {
		strncpy(ip, "0.0.0.0", max_len);
		return -1;
	}
	
	// Check if the address is IPv4 or IPv6
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		if (inet_ntop(AF_INET, &s->sin_addr, ip, max_len) == NULL) {
			strncpy(ip, "0.0.0.0", max_len);
			return -1;
		}
	} else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		if (inet_ntop(AF_INET6, &s->sin6_addr, ip, max_len) == NULL) {
			strncpy(ip, "0.0.0.0", max_len);
			return -1;
		}
	} else {
		strncpy(ip, "0.0.0.0", max_len);
		return -1;
	}
	
	return 0;
}

void *datum_threadpool_thread(void *arg) {
	T_DATUM_THREAD_DATA *my = (T_DATUM_THREAD_DATA *)arg;
	int i, nfds, n, cidx, j;
	size_t leftover = 0;
	
	if (!my->app->client_cmd_func) {
		DLOG_FATAL("Thread pool thread started with no client command function pointer. :(");
		panic_from_thread(__LINE__);
		return 0;
	}
	
	my->epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (my->epollfd < 0) {
		DLOG_FATAL("could not epoll_create!");
		panic_from_thread(__LINE__);
		return 0;
	}
	
	// Call application specific thread init
	if (my->app->init_func) my->app->init_func(my);
	
	while(1) {
		pthread_mutex_lock(&my->thread_data_lock);
		
		if (!my->connected_clients) {
			// no clients to serve
			// shutdown this thread after some kind of timeout?
			pthread_mutex_unlock(&my->thread_data_lock);
			
			// the loop doesn't care if we have no clients...
			if (my->app->loop_func) my->app->loop_func(my);
			
			my->has_client_kill_request = false;
			my->empty_request = false;
			
			usleep(10000);
			continue;
		}
		
		// check if any new clients, handle them if so
		if (my->has_new_clients) {
			for(i=0;i<my->app->max_clients_thread;i++) {
				if (my->client_data[i].new_connection) {
					my->client_data[i].new_connection = false;
					my->client_data[i].in_buf = 0;
					my->client_data[i].out_buf = 0;
					my->client_data[i].proxy_line_read = false;
					
					// add to epoll for this thread
					my->ev.events = EPOLLIN  | EPOLLONESHOT | EPOLLERR; // | EPOLLRDHUP
					my->ev.data.u64 = i; // store client index... duh
					if (epoll_ctl(my->epollfd, EPOLL_CTL_ADD, my->client_data[i].fd, &my->ev) < 0) {
						DLOG_ERROR("epoll_ctl add failed: %s", strerror(errno));
						close(my->client_data[i].fd); // Close the file descriptor on error
						
						// call closed client function, if any
						if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[i], "epoll_ctl add failed @ new connection");
						
						// we already have a lock on this thread's data here, so can (must) decrement wo/locking again
						datum_socket_thread_client_count_decrement(my, i, false);
						continue;
					}
					// call new client handler, if any
					if (my->app->new_client_func) my->app->new_client_func(&my->client_data[i]);
				}
			}
			my->has_new_clients = false;
		}
		pthread_mutex_unlock(&my->thread_data_lock);
		
		if (__builtin_expect(my->empty_request,0)) {
			// We got a request to empty all clients from our thread!
			DLOG_WARN("Executing command to empty thread (%d clients)",my->connected_clients);
			for (j = 0; j < my->app->max_clients_thread; j++) {
				if (my->client_data[j].fd != 0) {
					epoll_ctl(my->epollfd, EPOLL_CTL_DEL, my->client_data[j].fd, NULL);
					close(my->client_data[j].fd);
					
					// call closed client function, if any
					if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[j], "empty thread command");
					datum_socket_thread_client_count_decrement(my, j, true);
				}
			}
		} else if (__builtin_expect(my->has_client_kill_request,0)) {
			// the API has requested we kill a specific client
			for (j = 0; j < my->app->max_clients_thread; j++) {
				if ((my->client_data[j].fd != 0) && (my->client_data[j].kill_request)) {
					my->client_data[j].kill_request = false;
					epoll_ctl(my->epollfd, EPOLL_CTL_DEL, my->client_data[j].fd, NULL);
					close(my->client_data[j].fd);
					
					// call closed client function, if any
					if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[j], "client kill command");
					datum_socket_thread_client_count_decrement(my, j, true);
				}
			}
		}
		my->has_client_kill_request = false;
		my->empty_request = false;
		// Call application specific thread preloop
		if (my->app->loop_func) my->app->loop_func(my);
		
		// TODO: make this smarter
		// See if there's anything to write for any of our clients before looping through all potential clients.
		// Will need profiling, as this is pretty cheap to do with reasonable max_clients_thread.
		// If there's data, attempt to send it.
		for (j = 0; j < my->app->max_clients_thread; j++) {
			if ((my->client_data[j].fd != 0) && (my->client_data[j].out_buf > 0)) {
				int sent = send(my->client_data[j].fd, my->client_data[j].w_buffer, my->client_data[j].out_buf, MSG_DONTWAIT);
				if (sent > 0) {
					if (sent < my->client_data[j].out_buf) {
						// not a full send. shift remaining data to beginning of w_buffer
						memmove(my->client_data[j].w_buffer, my->client_data[j].w_buffer + sent, my->client_data[j].out_buf - sent);
					}
					if (sent <= my->client_data[j].out_buf) {
						my->client_data[j].out_buf -= sent;
					} else {
						// should never happen
						my->client_data[j].out_buf = 0;
					}
				} else {
					if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
						epoll_ctl(my->epollfd, EPOLL_CTL_DEL, my->client_data[j].fd, NULL);
						close(my->client_data[j].fd);
						
						// call closed client function, if any
						if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[j], "send error");
						
						datum_socket_thread_client_count_decrement(my, j, true);
					}
				}
			}
		}
		
		// check if we have any data to read from any existing clients
		nfds = epoll_wait(my->epollfd, my->events, MAX_EVENTS, 7);
		if (nfds < 0) {
			if (errno != EINTR) {
				DLOG_ERROR("epoll_wait returned %d", nfds);
				sleep(1);
				continue;
			}
		}
		if (nfds) {
			for(i=0;i<nfds;i++) {
				cidx = my->events[i].data.u64;
				
				if (cidx >= 0) {
					n = recv(my->client_data[cidx].fd, &my->client_data[cidx].buffer[my->client_data[cidx].in_buf], CLIENT_BUFFER - 1 - my->client_data[cidx].in_buf, MSG_DONTWAIT);
					if (n <= 0) {
						if ((n < 0) && ((errno == EAGAIN || errno == EWOULDBLOCK))) {
							// we epoll'd without edge triggering.  this shouldn't happen!
							DLOG_DEBUG("recv returned would block or again! shouldn't happen?");
							continue; // continue for loop
						} else {
							// an error occurred or the client closed the connection
							DLOG_DEBUG("Thread %03d epoll --- Closing fd %d (n=%d) errno=%d (%s) (req bytes: %d)", my->thread_id, my->client_data[cidx].fd, n, errno, strerror(errno), CLIENT_BUFFER - 1 - my->client_data[cidx].in_buf);
							epoll_ctl(my->epollfd, EPOLL_CTL_DEL, my->client_data[cidx].fd, NULL);
							close(my->client_data[cidx].fd);
							
							// call closed client function, if any
							if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "client closed connection");
							
							datum_socket_thread_client_count_decrement(my, cidx, true);
						}
					} else {
						// null terminate the buffer for simplicity
						// this set of functions is currently only used for stratum v1-like protocols, but can easily be adopted to others.
						my->client_data[cidx].buffer[my->client_data[cidx].in_buf+n] = 0;
						
						char *start_line = my->client_data[cidx].buffer;
						char *end_line = strchr(start_line, '\n');
						
						while (end_line != NULL) {
							*end_line = 0; // null terminate the line
							// this function can not be NULL
							if (!my->client_data[cidx].proxy_line_read && strncmp(start_line, "PROXY ", 6) == 0) {
								my->client_data[cidx].proxy_line_read = true;
								if (datum_config.stratum_v1_trust_proxy) {
									char src_ip[DATUM_MAX_IP_LEN] = {0};
									sscanf(start_line, "PROXY TCP4 %15s", src_ip);
									if (src_ip[0] == 0) sscanf(start_line, "PROXY TCP6 %45s", src_ip);
									strncpy(my->client_data[cidx].rem_host, src_ip, DATUM_MAX_IP_LEN-1);
								}
								start_line = end_line + 1;
								end_line = strchr(start_line, '\n');
								continue;
							}
							j = my->app->client_cmd_func(&my->client_data[cidx], start_line);
							if (j < 0) {
								//LOG_PRINTF("Thread %03d --- Closing fd %d (client_cmd_func returned %d)", my->thread_id, my->client_data[cidx].fd, j);
								epoll_ctl(my->epollfd, EPOLL_CTL_DEL, my->client_data[cidx].fd, NULL);
								close(my->client_data[cidx].fd);
								
								// call closed client function, if any
								if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "client_cmd_func returned error");
								
								datum_socket_thread_client_count_decrement(my, cidx, true);
								start_line[0] = 0;
								break;
							}
							start_line = end_line + 1;
							end_line = strchr(start_line, '\n');
						}
						
						// If any data is leftover, shift it to the beginning of the buffer
						// TODO: Implement a buffer type that doesn't require memmove on a partial read
						if (start_line[0] != 0) {
							leftover = strlen(start_line); // we null terminate the buffer above
							if (leftover) {
								memmove(my->client_data[cidx].buffer, start_line, leftover+1); // we null terminated the read above, remember?
							}
						} else {
							leftover = 0;
						}
						my->client_data[cidx].in_buf = leftover;
						if (my->client_data[cidx].in_buf >= (CLIENT_BUFFER - 1)) {
							// buffer overrun. lose the data. will probably break things, so punt the client. this shouldn't happen with sane clients.
							my->client_data[cidx].in_buf = 0;
							my->client_data[cidx].buffer[0] = 0;
							
							epoll_ctl(my->epollfd, EPOLL_CTL_DEL, my->client_data[cidx].fd, NULL);
							close(my->client_data[cidx].fd);
							
							// call closed client function, if any
							if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "read buffer overrun before client command break");
							
							datum_socket_thread_client_count_decrement(my, cidx, true);
						}
					}
				}
				
				if (my->client_data[cidx].fd > 0) {
					// re-add to epoll for this client
					my->ev.events = EPOLLIN | EPOLLONESHOT;
					my->ev.data.u64 = cidx; // store client index... duh
					if (epoll_ctl(my->epollfd, EPOLL_CTL_MOD, my->client_data[cidx].fd, &my->ev) < 0) {
						// if this fails, there's probably some bad things happening.  In any case, we can't continue serving this client so we should punt them.
						DLOG_ERROR("epoll_ctl mod for client %d", cidx);
						close(my->client_data[cidx].fd); // Close the file descriptor on error
						
						// call closed client function, if any
						if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "epoll_ctl error re-upping client polling");
						
						datum_socket_thread_client_count_decrement(my, cidx, true);
						
						continue;
					}
				}
			}
		}
	}
	
	return NULL;
}

void clean_thread_data(T_DATUM_THREAD_DATA *d, T_DATUM_SOCKET_APP *app) {
	int i,ret;
	
	// clean up clients, just in case
	for(i=0;i<app->max_clients_thread;i++) {
		d->client_data[i].new_connection = false;
		d->client_data[i].fd = 0;
		d->client_data[i].in_buf = 0;
		d->client_data[i].out_buf = 0;
	}
	
	d->connected_clients = 0;
	d->next_open_client_index = 0;
	
	d->has_new_clients = false;
	
	// clear polling events
	// TODO: dynamic allocation of buffers
	memset(&d->ev, 0, sizeof(struct epoll_event));
	memset(d->events, 0, sizeof(struct epoll_event) * MAX_CLIENTS_THREAD*2);
	
	// init the mutex
	ret = pthread_mutex_init(&d->thread_data_lock, NULL);
	if (ret) {
		DLOG_FATAL("Could not init mutex for thread data: %s", strerror(ret));
		panic_from_thread(__LINE__);
		return;
	}
	
	// fix the app pointer
	d->app = app;
}

int assign_to_thread(T_DATUM_SOCKET_APP *app, int fd) {
	// Only one thread will be calling this function for a particular "app"
	// under the current design.  Safe to assume that multiple clients will
	// not cause overlap here.
	
	// Check how many threads are active.
	// If < max, put the client on a new thread.
	// If all threads are active, then it should find the one with the fewest clients and place the new client there.
	
	int i,j,ret,tc=0;
	
	int tid=-1,cid=-1;
	
	if (app->datum_active_threads < app->max_threads) {
		// we have not launched all threads yet, or somehow a thread has become inactive
		// place this connection on it's own new thread
		
		// let's assume, for now, that if we don't have all threads active that we're not above max_clients
		
		// find the first inactive thread
		for(i=0;i<app->max_threads;i++) {
			// safe to read this without locking, as we're the only one that should be updating it
			if (!app->datum_threads[i].is_active) {
				tid = i;
				break;
			}
		}
		
		if (tid == -1) {
			DLOG_ERROR("Possible bug in thread handler. Could not find an inactive thread. datum_active_threads = %d; max_threads = %d", app->datum_active_threads, app->max_threads);
			return 0;
		}
		
		// clean up thread starting data
		clean_thread_data(&app->datum_threads[tid], app);
		
		app->datum_threads[tid].thread_id = tid;
		app->datum_threads[tid].is_active = true;
		
		if (pthread_create(&app->datum_threads[i].pthread, NULL, datum_threadpool_thread, &app->datum_threads[i]) != 0) {
			DLOG_ERROR("Could not start new thread for TID %d", tid);
			return 0;
		}
		app->datum_active_threads++;
	} else {
		// active threads are maxed already.  find one with the fewest clients
		// in general, it should be safe to read the client count without locking, since
		// we don't particularly care _right here_ if it's higher than expected from a client
		// disconnection.  We're the only one that increments it.
		
		// TODO: Profile if locking/unlocking here is sufficiently slow to care or not on the performance side
		// We don't want to make a clean path to a DoS, even though this is intended as a local service for local miners.
		
		j = app->max_clients_thread;
		
		// find the thread with the lowest client count
		// also tally up the total clients
		for(i=0;i<app->max_threads;i++) {
			if (app->datum_threads[i].connected_clients < j) {
				j = app->datum_threads[i].connected_clients;
				tid = i;
			}
			tc+=app->datum_threads[i].connected_clients;
		}
		
		if (tid == -1) {
			DLOG_INFO("All threads have max clients! Rejecting connection. :(");
			return 0;
		}
		
		if (tc >= app->max_clients) {
			DLOG_INFO("Sum of clients on all threads at configured global maximum (%d) Rejecting connection. :(", app->max_clients);
			return 0;
		}
	}
	
	// lock the thread's data for a moment
	ret = pthread_mutex_lock(&app->datum_threads[tid].thread_data_lock);
	if (ret != 0) {
		DLOG_FATAL("Could not lock mutex for thread data on TID %d: %s", tid, strerror(ret));
		panic_from_thread(__LINE__); // Is this panic worthy? should never happen
		return 0;
	}
	
	// sanity check
	if (app->datum_threads[tid].connected_clients >= app->max_clients_thread) {
		pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
		DLOG_ERROR("Attempted to assign client to thread %d, which already has MAX CLIENTS %d >= %d", tid, app->datum_threads[tid].connected_clients, app->max_clients_thread);
		return 0;
	}
	
	// get the client's cid
	cid = app->datum_threads[tid].next_open_client_index;
	
	// sanity check: confirm this cid is usable
	if (app->datum_threads[tid].client_data[cid].fd != 0) {
		DLOG_ERROR("Possible bug: Desync with next_open_client_index.  Expected open client slot @ %d on non-maxed thread %d! (shows fd = %d)", cid, tid, app->datum_threads[tid].client_data[cid].fd);
		
		// let's try the hard way to find an open slot
		cid = -1;
		for(i=0;i<app->max_clients_thread;i++) {
			if (app->datum_threads[tid].client_data[i].fd == 0) {
				cid = i;
				break;
			}
		}
		
		if (cid != -1) {
			DLOG_ERROR("Possible bug: Found an open client slot the hard way. Recovering. TID=%d CID=%d", tid, cid);
		} else {
			DLOG_ERROR("Possible bug: Could not find an open client slot the hard way! Rejecting client for TID=%d (%d clients)", tid, app->datum_threads[tid].connected_clients);
			pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
			return 0;
		}
	}
	
	// prep the next open CID by finding the next open slot
	app->datum_threads[tid].next_open_client_index = cid + 1;
	if (app->datum_threads[tid].next_open_client_index == app->max_clients_thread) app->datum_threads[tid].next_open_client_index = 0;
	
	// prep the next open CID
	for(i=app->datum_threads[tid].next_open_client_index; i != cid;) {
		if (app->datum_threads[tid].client_data[i].fd == 0) {
			// i is good
			app->datum_threads[tid].next_open_client_index = i;
			break;
		}
		
		// loop i around
		i++;
		if (i >= app->max_clients_thread) i = 0;
	}
	
	if (i == cid) {
		// we couldn't find an open client slot for the next client :(
		DLOG_DEBUG("Placing client on maxed out thread TID=%d CID=%d ... Thread is now FULL!",tid,cid);
		app->datum_threads[tid].next_open_client_index = app->max_clients_thread-1;
	}
	
	// bump connected client count
	app->datum_threads[tid].connected_clients++;
	
	// clear up and prep slot's client data without clobbering app_client_data
	app->datum_threads[tid].client_data[cid].fd = fd;
	app->datum_threads[tid].client_data[cid].cid = cid;
	app->datum_threads[tid].client_data[cid].new_connection = true;
	app->datum_threads[tid].client_data[cid].datum_thread = (void *)&app->datum_threads[tid];
	app->datum_threads[tid].client_data[cid].in_buf = 0;
	app->datum_threads[tid].client_data[cid].out_buf = 0;
	app->datum_threads[tid].has_new_clients = true;
	
	pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
	
	if (!tc) {
		// tally clients for our debug
		for(i=0;i<app->max_threads;i++) {
			tc+=app->datum_threads[i].connected_clients;
		}
	} else {
		tc++;
	}
	
	get_remote_ip(&app->datum_threads[tid].client_data[cid], app->datum_threads[tid].client_data[cid].rem_host, DATUM_MAX_IP_LEN);
	
	DLOG_DEBUG("New client (%s) on TID %d, CID %d with fd %d. clients: %d / clients on thread: %d", app->datum_threads[tid].client_data[cid].rem_host, tid, cid, fd, tc, app->datum_threads[tid].connected_clients);
	DLOG_DEBUG("app->datum_threads[tid].next_open_client_index = %d", app->datum_threads[tid].next_open_client_index);
	return 1;
}

const char *datum_sockets_setup_listen_sock(const int listen_sock, const struct sockaddr * const sa, const size_t sa_len) {
	if (-1 == listen_sock) {
		return "Could not create listening socket";
	}
	
	datum_socket_setoptions(listen_sock);
	
	static const int reuse = 1;
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
		return "setsockopt(SO_REUSEADDR) failed";
	}
	
	if (bind(listen_sock, sa, sa_len) < 0) {
		return "bind failed";
	}
	
	if (listen(listen_sock, 10) < 0) {
		return "listen failed";
	}
	
	return NULL;
}

bool datum_sockets_setup_listening_sockets(const char * const purpose, const char * const addr, const uint16_t port, int * const out_socks, size_t * const inout_socks_n) {
	assert(*inout_socks_n > 0);
	if (addr && addr[0]) {
		char port_str[6];
		snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);
		const struct addrinfo hints = {
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = 0,
			.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV,
		};
		struct addrinfo *res;
		int err = getaddrinfo(addr, port_str, &hints, &res);
		if (err) {
			DLOG_FATAL("Failed to resolve listen address '%s' (%s): %s", purpose, addr, gai_strerror(err));
			panic_from_thread(__LINE__);
			return false;
		}
		*out_socks = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		const char *errstr = datum_sockets_setup_listen_sock(*out_socks, res->ai_addr, res->ai_addrlen);
		const int errno_saved = errno;
		freeaddrinfo(res);
		if (errstr) {
			DLOG_FATAL("%s (%s): %s", errstr, purpose, strerror(errno_saved));
			panic_from_thread(__LINE__);
			return false;
		}
		*inout_socks_n = 1;
	} else {
		const struct sockaddr_in6 anyaddr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(port),
			.sin6_addr = IN6ADDR_ANY_INIT,
		};
		out_socks[0] = socket(AF_INET6, SOCK_STREAM, 0);
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		if (out_socks[0] != -1) {
			static const int zero = 0;
			setsockopt(out_socks[0], IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
		}
#endif
		const char * const errstr6 = datum_sockets_setup_listen_sock(out_socks[0], (const struct sockaddr *)&anyaddr6, sizeof(anyaddr6));
		const int errno6 = errno;
		unsigned int socks_n = 1;
		if (errstr6 && out_socks[0] != -1) {
			close(out_socks[0]);
			out_socks[0] = -1;
			--socks_n;
		}
		
		if (*inout_socks_n > socks_n) {
			const struct sockaddr_in anyaddr4 = {
				.sin_family = AF_INET,
				.sin_port = htons(port),
				.sin_addr.s_addr = INADDR_ANY,
			};
			out_socks[socks_n] = socket(AF_INET, SOCK_STREAM, 0);
			const char *errstr = datum_sockets_setup_listen_sock(out_socks[socks_n], (const struct sockaddr *)&anyaddr4, sizeof(anyaddr4));
			if (errstr && errstr6) {
				const int errno4 = errno;
				DLOG_FATAL("%s (IPv6): %s", errstr6, strerror(errno6));
				DLOG_FATAL("%s (IPv4): %s", errstr, strerror(errno4));
				panic_from_thread(__LINE__);
				return false;
			}
			if (errstr && out_socks[socks_n] != -1) {
				close(out_socks[socks_n]);
				out_socks[socks_n] = -1;
			} else {
				++socks_n;
			}
		}
		
		*inout_socks_n = socks_n;
	}
	return true;
}

void *datum_gateway_listener_thread(void *arg) {
	int i, ret;
	bool rejecting_now = false;
	uint64_t last_reject_msg_tsms = 0, curtime_tsms = 0;
	uint64_t reject_count = 0;
	
	T_DATUM_SOCKET_APP *app = (T_DATUM_SOCKET_APP *)arg;
	
	struct epoll_event ev, events[MAX_EVENTS];
	int listen_socks[2], conn_sock, nfds, epollfd;
	
	if (!app) {
		DLOG_FATAL("Called without application data structure. :(");
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	DLOG_DEBUG("Setting up app '%s' on address %s port %d. (T:%d/TC:%d/C:%d)", app->name, datum_config.stratum_v1_listen_addr[0] ? datum_config.stratum_v1_listen_addr : "(any)", app->listen_port, app->max_threads, app->max_clients_thread, app->max_clients);
	
	// we assume the caller sets up the thread data in some way
	// don't clobber those pointers
	for(i=0;i<app->max_threads;i++) {
		ret = pthread_mutex_init(&app->datum_threads[i].thread_data_lock, NULL);
		if (ret) {
			DLOG_FATAL("Could not init mutex for thread data: %s", strerror(ret));
			panic_from_thread(__LINE__);
			return NULL;
		}
		
		// set app data pointer
		app->datum_threads[i].app = app;
		app->datum_threads[i].thread_id = i;
		app->datum_threads[i].connected_clients = 0;
		app->datum_threads[i].next_open_client_index = 0;
	}
	
	app->datum_active_threads = 0;
	
	size_t listen_socks_len = 2;
	if (!datum_sockets_setup_listening_sockets("stratum", datum_config.stratum_v1_listen_addr, app->listen_port, listen_socks, &listen_socks_len)) {
		return NULL;
	}
	if (listen_socks_len < 2) listen_socks[1] = -1;
	
	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		DLOG_FATAL("epoll_create1 failed: %s", strerror(errno));
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	for (i = 0; i < 2; ++i) {
		if (listen_socks[i] == -1) continue;
		ev.events = EPOLLIN;
		ev.data.fd = listen_socks[i];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0) {
			DLOG_FATAL("epoll_ctl failed: %s", strerror(errno));
			panic_from_thread(__LINE__);
			return NULL;
		}
	}
	
	DLOG_INFO("DATUM Socket listener thread active for '%s'", app->name);
	
	for (;;) {
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, 100);
		if (nfds) {
			if (datum_config.datum_pooled_mining_only && (!datum_protocol_is_active())) {
				curtime_tsms = current_time_millis(); // we only need this if we're rejecting connections
				if (!rejecting_now) {
					last_reject_msg_tsms = curtime_tsms - 5000; // first disconnect triggers msg
				}
				rejecting_now = true;
			} else {
				rejecting_now = false;
			}
		}
		for (int n = 0; n < nfds; ++n) {
			if (events[n].data.fd == listen_socks[0] || events[n].data.fd == listen_socks[1]) {
				conn_sock = accept(events[n].data.fd, NULL, NULL);
				if (conn_sock < 0) {
					DLOG_ERROR("accept failed: %s", strerror(errno));
					continue;
				}
				
				if (rejecting_now) {
					reject_count++;
					if ((curtime_tsms - last_reject_msg_tsms) > 5000) {
						DLOG_INFO("DATUM not connected and configured for pooled mining only! Rejecting connection. (%llu connections rejected since last noted)", (unsigned long long)reject_count);
						last_reject_msg_tsms = curtime_tsms;
						reject_count = 0;
					}
					close(conn_sock);
					continue;
				}
				
				DLOG_DEBUG("Accepted socket to fd %d", conn_sock);
				datum_socket_setoptions(conn_sock);
				
				// assign socket to a thread
				i = assign_to_thread(app, conn_sock);
				if (!i) {
					// error finding a thread (too many connections?)
					DLOG_DEBUG("Closing socket we couldn't assign %d", conn_sock);
					close(conn_sock);
				}
			}
		}
	}
	
	return NULL;
}

void datum_socket_setoptions(int sock) {
	int opts;
	int flag = 1;
	
	opts = fcntl(sock,F_GETFL);
	if (opts < 0) {
		DLOG_FATAL("fcntl(F_GETFL) failed: %s", strerror(errno));
		panic_from_thread(__LINE__);
	}
	opts = (opts | O_NONBLOCK);
	if (fcntl(sock,F_SETFL,opts) < 0) {
		DLOG_FATAL("fcntl(F_SETFL) failed: %s", strerror(errno));
		panic_from_thread(__LINE__);
	}
	
	// Set the TCP_NODELAY option
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0) {
		DLOG_FATAL("setsockopt(TCP_NODELAY) failed: %s", strerror(errno));
		panic_from_thread(__LINE__);
	}
}

int datum_socket_send_string_to_client(T_DATUM_CLIENT_DATA *c, char *s) {
	int len = strlen(s);
	if (!len) return 0;
	if ((c->out_buf + len) >= CLIENT_BUFFER) return -1;
	strncpy(&c->w_buffer[c->out_buf], s, CLIENT_BUFFER-(c->out_buf)-1);
	c->out_buf += len;
	return len;
}

int datum_socket_send_chars_to_client(T_DATUM_CLIENT_DATA *c, char *s, int len) {
	if (!len) return 0;
	if ((c->out_buf + len) >= CLIENT_BUFFER) return -1;
	if (len > (CLIENT_BUFFER-(c->out_buf)-1)) {
		len = CLIENT_BUFFER-(c->out_buf)-1;
	}
	memcpy(&c->w_buffer[c->out_buf], s, len);
	c->out_buf += len;
	return len;
}
