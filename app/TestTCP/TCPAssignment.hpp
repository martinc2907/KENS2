/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <E/E_TimerModule.hpp>

#include <cstdlib>

namespace E
{

struct socket{

	UUID uuid;

	int pid; 	//seems like  sockets for all processes taken care of here. therefore, search requires pid.

	bool bound;	//bound on connect(implicit) or bind(explicit)
	bool listen;

	unsigned sequence_number;

	int fd;

	/* Things for listening socket */
	int backlog;	//for how many incoming connections can be queued.
	std::list<struct socket *> * estab_list;
	struct socket * listening_socket;
	struct sockaddr* sockaddr;//need to put values in here for fake accept
	bool accept_block;	

	//client starts with listen.
	//server only listen after calling listen.
	int client_state;	//0,1,2 listen, synsent estab
	int server_state;	//0,1,2 listen, synrcvd, estab

	unsigned short source_port;
	unsigned long source_ip;

	unsigned short dest_port;
	unsigned long dest_ip;
};


//20 bytes.
struct TCP_header{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned sequence_number;
	unsigned ack_number;
	char first_byte;
	char flags;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_ptr;
}__attribute__((packed));

struct pseudoheader
{
	uint32_t source;
	uint32_t destination;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
}__attribute__((packed));

// enum client_state {LISTEN, SYNSENT, ESTAB};
// enum server_state {LISTEN, SYNRCVD, ESTAB};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	unsigned short max_port = 32768; //ephemeral ports: 32768 - 61000(Linux)
	// UUID uuid;

	int debug_count = 0;
	//client starst with listen.
	int client_state = 0;	//0,1,2 listen synsent estab
	int server_state = -1;	//0,1,2 listen, synrcvd, estab

private:
	virtual void timerCallback(void* payload) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int);
	virtual void syscall_close(UUID syscallUUID, int pid, int param1_int);
	virtual void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr *ptr,socklen_t param3_int);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int param1_int, struct sockaddr * sa, socklen_t * socklen);
	virtual void syscall_connect(UUID syscallUUID, int pid, int param1_int, struct sockaddr* sa, socklen_t socklen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd,struct sockaddr * addr, socklen_t * addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* sa, socklen_t * len);

	virtual struct socket * find_socket_dest(unsigned long dest_ip, unsigned short dest_port);
	virtual struct socket * find_socket_source(unsigned long source_ip, unsigned short source_port);
	virtual struct socket * find_listening_socket_source(unsigned long source_ip, unsigned short source_port);
	virtual struct socket * find_fd(int pid,int fd);
	virtual bool check_overlap(int fd, unsigned long ip, unsigned short port);
	virtual bool check_overlap_normalsock(int fd, unsigned long ip, unsigned short port);
	virtual void bind(int fd, unsigned long ip, unsigned short port);
	virtual struct socket * create_socket(int pid, int fd);
	virtual void remove_fd(int fd);
	virtual unsigned short get_port();
	virtual void fake_accept(struct socket * listening_socket);

	virtual uint16_t tcp_sum(uint32_t source, uint32_t dest, uint8_t* buffer, size_t length);
	virtual uint16_t one_sum(uint8_t* buffer, size_t size);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	std::list<struct socket *> socket_list;
	
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
