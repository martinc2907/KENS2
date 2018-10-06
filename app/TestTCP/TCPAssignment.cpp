/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

#include <list>
#include <assert.h>

#include <arpa/inet.h>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* sa, socklen_t * len){
	//return non-negative integer that is file descriptor for the new socket.
	//return -1 for error.
	//sockfd, sockaddr, len.
	//sockfd = listening socket.
	//sockaddr = info about incoming connection.

	struct socket * listening_socket = find_fd(pid,sockfd);
	struct socket * socket;


	/* There are completed connections */
	if(listening_socket->estab_list != NULL && !(listening_socket->estab_list->empty())){
		socket = listening_socket->estab_list->front();
		listening_socket->estab_list->pop_front();

		std::cout<<"accept nonblock(new socket): "<< socket->source_ip << ","<<socket->source_port << ","<< socket->dest_ip << ","<< socket->dest_port<< "\n";

		//fill in sockaddr with new socket information?
		struct sockaddr_in * si = (struct sockaddr_in *) sa;
		struct in_addr * ia = (struct in_addr *) (&(si->sin_addr));
		ia->s_addr = socket->dest_ip;
		si->sin_family = AF_INET;
		si->sin_port = htons(socket->dest_port);


		this->returnSystemCall(syscallUUID, socket->fd);
		return;
	}
	std::cout<<"accept block\n";


	//if no, completed connection, nothing. just blocked.
	//will be unblocked by fake_accept from packetArrived function.
	//give uuid to listening socket.
	listening_socket->accept_block = true;
	listening_socket->uuid = syscallUUID;
	listening_socket->sockaddr = sa;
}

//Two scenarios:
//1) Connection established before accept.
//2) Accept before connection
		//-> blocked accept -> fakeaccept called -> uuid reset -> accept returns.

//only called when accept was called already.
void TCPAssignment::fake_accept(struct socket * listening_socket){

	struct socket * socket;
	UUID syscallUUID = listening_socket->uuid;

	/* There are completed connections. */
	if(listening_socket->estab_list != NULL && !(listening_socket->estab_list->empty())){
		socket = listening_socket->estab_list->front();
		listening_socket->estab_list->pop_front();

		//fill in sockaddr with new socket information?
		struct sockaddr_in * si = (struct sockaddr_in *) listening_socket->sockaddr;
		struct in_addr * ia = (struct in_addr *) (&(si->sin_addr));
		ia->s_addr = socket->dest_ip;
		si->sin_family = AF_INET;
		si->sin_port = htons(socket->dest_port);

		//accept consumed one connection, so reset uuid value for another accept call.
		listening_socket->accept_block = false;
		listening_socket->uuid = 0;
		listening_socket->sockaddr = NULL;
		this->returnSystemCall(syscallUUID, socket->fd);
	}

}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	
	//return 0 on success, -1 on error.
	struct socket * socket = find_fd(pid, sockfd);

	if(find_socket_source(socket->source_ip, socket->source_port) == NULL){
		std::cout<<"ASDFOIQJWEOIJOIJWE\n";
	}

	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	//mark it listen - important for searching later.
	socket->listen = true;
	socket->backlog = backlog;

	std::cout<<"listen: " << socket->source_ip << "," <<socket->source_port << "\n";

	if(find_listening_socket_source(socket->source_ip, socket->source_port) == NULL){
		std::cout<<"ASDFOIQJWEOIJOIJWE\n";
	}

	socket->server_state = 0; // state = listen

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,struct sockaddr * addr, socklen_t * addrlen){
	/* Return 0 on success, -1 on error */

	// initialise to this always?
	*addrlen = sizeof(struct sockaddr);

	//find peer adddress by looking at socket.
	struct socket * socket = find_fd(pid, sockfd);
	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in * si = (struct sockaddr_in *) addr;
	struct in_addr * ia= (struct in_addr *) (&(si->sin_addr));

	//set ip.
	ia->s_addr = socket->dest_ip;

	//set sin_family in sockaddr_in
	si->sin_family = AF_INET;

	//set sin_port in sockaddr_in
	si->sin_port = htons(socket->dest_port);

	this->returnSystemCall(syscallUUID, 0);
	//DIDN'T DO THE LENGHT CUT OFF STUFF. RETS DIFFERENT VALUES?
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int){
	int fd = this->createFileDescriptor(pid);
	create_socket(pid, fd);
	this->returnSystemCall(syscallUUID, fd);//systemcallinterface function.
}


void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int param1_int, struct sockaddr*sa, socklen_t socklen){
	unsigned short source_port = 0;	//dest and source addrs.
	unsigned long source_ip = 0;
	unsigned short dest_port = 0;
	unsigned long dest_ip = 0;

	int index = 0;	//other declarations.
	bool success;
	Host * host;

	/* Implicit bind- fill in socket. */
	struct socket * socket = find_fd(pid, param1_int);
	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	else if(socket->bound){	//use address in socket if bound already.
		source_ip = socket->source_ip;
		source_port = socket->source_port;
	}
	else{
		// Get source ip and port
		host = this->getHost();
		index = host->getRoutingTable( (uint8_t*) &(dest_ip) );
		success = host->getIPAddr( (uint8_t*)(&source_ip), index);
		if(!success){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		source_port = get_port();

		/* Check overlap then bind. */
		if(check_overlap(param1_int, source_ip, source_port)){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}else{
			bind(param1_int, source_ip, source_port);
		}
	}


	/* Extract destination address */
	struct sockaddr_in * si = (struct sockaddr_in *) sa;
	dest_ip = (&(si->sin_addr))->s_addr;
	dest_port = ntohs(si->sin_port);
	socket->dest_ip = dest_ip; //do not assign destinatino port, because this is listenig port.
	socket->dest_port = dest_port;


	/* Make SYN packet */
	//0~13 = Link, 14~33 = IP, 34~53 = TCP
	Packet * packet = this->allocatePacket(54);
	packet->writeData(14+12, &source_ip, 4);	//src ip
	packet->writeData(14+16, &dest_ip, 4);		//dest ip

	struct TCP_header * header = new struct TCP_header;
	// header->source_port = htons(46759);
	header->source_port = htons(source_port);			//TCP header only takes port,since it's transport layer.
	header->dest_port = htons(dest_port);
	header->sequence_number = htonl(socket->sequence_number);
	socket->sequence_number++;
	header->ack_number = 0;							//ACK not set, so just put 0.
	header->first_byte = (5<<4);					//header size = 20bytes(5 words)
	header->flags = 0b00000010;
	header->window_size = htons(51200);
	header->urgent_ptr = 0;
	header->checksum = 0;
	header->checksum = htons(~(this->tcp_sum((source_ip), (dest_ip), (uint8_t*)header, 20)));
	packet->writeData(34, header, 20);

	/* Free struct */
	delete(header);

	/* update socket states */
	socket->client_state = 1;
	socket->uuid = syscallUUID;	//since connect is blocking.

	/* Send SYN packet-> */
	socket->client_state = 1;
	this->sendPacket("IPv4", packet);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1_int){
	int fd = param1_int;
	remove_fd(fd);
	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID,0);//what to return?
}


//bind is only for server.
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * sa,
				socklen_t param3_int){
	struct sockaddr_in * si = (struct sockaddr_in *) sa;
	unsigned short source_port = ntohs(si->sin_port);
	struct in_addr ia= (struct in_addr) (si->sin_addr);
	long source_ip = ia.s_addr;


	if(check_overlap(sockfd, source_ip, source_port)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}else{
		bind(sockfd, source_ip, source_port);
		this->returnSystemCall(syscallUUID, 0);
		return;
	}


}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, 
	struct sockaddr * sa, socklen_t * socklen){

	struct socket * e = find_fd(pid, fd);
	if(e == NULL){
		this->returnSystemCall(syscallUUID,-1);
		return;
	}

	struct sockaddr_in * si = (struct sockaddr_in *) sa;
	struct in_addr * ia= (struct in_addr *) (&(si->sin_addr));

	//set ip.
	ia->s_addr = e->source_ip;

	//set sin_family in sockaddr_in
	si->sin_family = AF_INET;

	//set sin_port in sockaddr_in
	si->sin_port = htons(e->source_port);

	this->returnSystemCall(syscallUUID,0);
}

		


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	Packet * new_packet;

	struct TCP_header * rcv_header = new struct TCP_header;
	struct TCP_header * new_header = new struct TCP_header;

	unsigned long sender_src_ip = 0;
	unsigned short sender_src_port = 0;
	unsigned long sender_dest_ip = 0;
	unsigned short sender_dest_port = 0;

	/* Read ip, port, and TCP Header */	
	packet->readData(14 + 12, &sender_src_ip, 4);		//ip
	packet->readData(14 + 16, &sender_dest_ip, 4);
	packet->readData(34 + 0, (void *)rcv_header, 20);	//header
	sender_src_port = ntohs(rcv_header->source_port);	//port
	sender_dest_port = ntohs(rcv_header->dest_port);

	/* Free packet */
	freePacket(packet);

	/* Server Side 3-way Connection */		
	if( ((rcv_header->flags & 0b00000010)>>1) && (!((rcv_header->flags & 0b00010000)>>1)) ){	//if syn and not ack.
	
		// std::cout<<"connection request\n";

		/* Find listening socket */
		struct socket * socket = find_listening_socket_source(sender_dest_ip, sender_dest_port);
		if(socket == NULL){
			//do sth
			return;
		}

		/* Verify */
		if( tcp_sum(sender_src_ip, sender_dest_ip, (uint8_t *)rcv_header, 20) != 0xffff){
			//do sth.
			return;
		}
		assert(socket->listen);

		/* Create new socket */
		int fd = this->createFileDescriptor(socket->pid);
		struct socket * new_socket = create_socket(socket->pid, fd);
		if(check_overlap_normalsock(fd, sender_dest_ip, sender_dest_port)){
			//if overlap with normal socket.
			remove_fd(fd);
			removeFileDescriptor(socket->pid, fd);
			return;
		}
		bind(fd, sender_dest_ip, sender_dest_port);
		new_socket->dest_port = sender_src_port;	//fill in dest
		new_socket->dest_ip = sender_src_ip;
		new_socket->server_state = 1;
		new_socket->listening_socket = socket;


		/* Send SYNACK */

		/* Allocate new packet and copy ip */
		new_packet = this->allocatePacket(54);
		new_packet->writeData(14 + 12, &sender_dest_ip, 4);	//src ip
		new_packet->writeData(14 + 16, &sender_src_ip, 4);	//dest ip

		/* Make return tcp header */
		new_header->source_port = rcv_header->dest_port;	//already network order.
		new_header->dest_port = rcv_header->source_port;
		new_header->sequence_number = htonl(new_socket->sequence_number);
		new_socket->sequence_number++;
		new_header->ack_number = htonl(ntohl(rcv_header->sequence_number)+1);
		new_header->first_byte = (5<<4);
		new_header->flags = 0b00010010;	//synbit = 1, ackbit = 1.
		new_header->window_size = htons(51200);
		new_header->urgent_ptr = 0;
		new_header->checksum = 0;
		new_header->checksum = htons(~(this->tcp_sum(sender_dest_ip, sender_src_ip, (uint8_t *)new_header, 20)));
		new_packet->writeData(34, new_header, 20);
		delete(rcv_header);
		delete(new_header);

		/* Send SYNACK Packet */
		this->sendPacket("IPv4", new_packet);
		return;
	}


	/* Client side 3-way Connection */
	else if(((rcv_header->flags & 0b00000010)>>1) && ((rcv_header->flags & 0b00010000)>>1) ){ //if syn and ack.
		/* Find appropriate socket for this destination */
		struct socket * socket = find_socket_source(sender_dest_ip, sender_dest_port);

		/* Verify */
		if( tcp_sum(sender_src_ip, sender_dest_ip, (uint8_t *)rcv_header, 20) != 0xffff){
			returnSystemCall(socket->uuid, -1);
			return;
		}
		if(socket->client_state != 1){
			returnSystemCall(socket->uuid, -1);
			return;
		}
		if( ntohl(rcv_header->ack_number) != socket->sequence_number){	//if wrong ack number.
			returnSystemCall(socket->uuid, -1);
			return;
		}

		/* Update states */
		socket->client_state = 2;

		/* Allocate new packet and copy ip */
		new_packet = this->allocatePacket(54);
		new_packet->writeData(14 + 12, &sender_dest_ip, 4);	//src ip
		new_packet->writeData(14 + 16, &sender_src_ip, 4);	//dest ip
		
		/* Make return tcp header */
		new_header->source_port = rcv_header->dest_port;	//already network order.
		new_header->dest_port = rcv_header->source_port;
		new_header->sequence_number = rcv_header->ack_number;
		new_header->ack_number = htonl(ntohl(rcv_header->sequence_number)+1);
		new_header->first_byte = (5<<4);
		new_header->flags = 0b00010000;	//synbit = 0, ackbit = 1.
		new_header->window_size = htons(51200);
		new_header->urgent_ptr = 0;
		new_header->checksum = 0;
		new_header->checksum = htons(~(this->tcp_sum(sender_dest_ip, sender_src_ip, (uint8_t *)new_header, 20)));
		new_packet->writeData(34, new_header, 20);
		delete(rcv_header);
		delete(new_header);

		/* Send ACK Packet */
		this->sendPacket("IPv4", new_packet);
		this->returnSystemCall(socket->uuid, 0);
		return;
	}

	/* Server. Synbit = 0, ack = 1*/
	else if((!((rcv_header->flags & 0b00000010)>>1)) && ((rcv_header->flags & 0b00010000)>>1)){
		
		std::cout<<"2nd connection request\n";
		/* Find socket you have created for it */
		struct socket * socket = find_socket_dest(sender_src_ip, sender_src_port);//demultiplex.
		if(socket == NULL){
			//do sth
			return;
		}


		/* Verify */
		if( tcp_sum(sender_src_ip, sender_dest_ip, (uint8_t *)rcv_header, 20) != 0xffff){
			return;
		}
		if(socket->server_state != 1){
			return;
		}
		if( ntohl(rcv_header->ack_number) != socket->sequence_number){		//if wrong ack number.
			return;
		}
		//should we do wrong sequence number too?

		/* Free */
		delete(rcv_header);
		delete(new_header);


		/* Connection established */
		socket->server_state = 2;

		/* Add this socket to listening socket's queue */
		struct socket * listening_socket = socket->listening_socket;
		if(listening_socket->estab_list == NULL){//if empty, initialise.
			listening_socket->estab_list = new std::list<struct socket *>;
		}
		if((unsigned)listening_socket->backlog == listening_socket->estab_list->size()){
			//do sth.
			return;
		}else{
			listening_socket->estab_list->push_back(socket);

			//call accept somehow. returnsystemcall(what uuid)...
			if(listening_socket->accept_block){
				fake_accept(listening_socket);
			}
		}
	}

}

void TCPAssignment::timerCallback(void* payload)
{

}

struct socket * TCPAssignment::find_socket_dest(unsigned long dest_ip, unsigned short dest_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if( e->listen == false && ((e->dest_ip == dest_ip) || e->dest_ip ==0) && e->dest_port == dest_port){
			return e;
		}
	}
	return NULL;
}

struct socket * TCPAssignment::find_listening_socket_source(unsigned long source_ip, unsigned short source_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if( e->listen == true && ((e->source_ip == source_ip) || e->source_ip ==0) && e->source_port == source_port){
			return e;
		}
	}
	return NULL;
}


struct socket * TCPAssignment::find_socket_source(unsigned long source_ip, unsigned short source_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if( e->listen == false && ((e->source_ip == source_ip) || e->source_ip ==0) && e->source_port == source_port){
			return e;
		}
	}
	return NULL;
}

//checks overlap with any type of socket.
bool TCPAssignment::check_overlap(int fd, unsigned long ip, unsigned short port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;

		//fd already bound.
		if(e->fd == fd && e->bound){
			return true;
		}

		//overlap.
		if( ((ip == e->source_ip)||(ip ==0)||(e->source_ip ==0)) && port == e->source_port){
			return true;
		}
	}
	return false;
}

//checks overlap with only normal sockets. if it's overlap with listening socket, it's ok.
bool TCPAssignment::check_overlap_normalsock(int fd, unsigned long ip, unsigned short port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;

		if(e->listen){
			continue;
		}

		//fd already bound.
		if(e->fd == fd && e->bound){
			return true;
		}

		//overlap.
		if( ((ip == e->source_ip)||(ip ==0)||(e->source_ip ==0)) && port == e->source_port){
			return true;
		}
	}
	return false;
}



//checks overlap with any socket.(no distinction between listening and normal socket).
void TCPAssignment::bind(int fd, unsigned long source_ip, unsigned short source_port){

	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(e->fd == fd){
			e->bound = true;
			e->source_port = source_port;
			e->source_ip = source_ip;
			break;
		}
	}
}

struct socket * TCPAssignment::find_fd(int pid, int fd){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(e->fd == fd && e->pid == pid){
			return e;
		}
	}
	return NULL;
}


void TCPAssignment::remove_fd(int fd){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(e->fd == fd){
			delete(e);
			socket_list.erase(it);
			break;
		}
	}
}

struct socket * TCPAssignment::create_socket(int pid, int fd){
	//assume list is called socket_list. list of struct pointers. 
	struct socket * e = new struct socket;

	e->accept_block = false;
	e->sockaddr = NULL;
	e->uuid = 0;
	e->listening_socket = NULL;
	e->pid = pid;
	e->estab_list = NULL;
	e->sequence_number = rand();
	e->client_state = 0;	//client starts with listen.
	e->server_state = -1;	//server only listen after calling listen.
	e->bound = false;
	e->listen = false;
	e->backlog = 0;
	e->fd = fd;
	e->source_ip = 0;
	e->source_port = 0;
	e->dest_ip = 0;
	e->dest_port = 0;

	socket_list.push_back(e);
	return e;
}

unsigned short TCPAssignment::get_port(){
	return max_port++;
}


uint16_t TCPAssignment::tcp_sum(uint32_t source, uint32_t dest, uint8_t* buffer, size_t length)
{
	if(length < 20)
		return 0;
	struct pseudoheader pheader;
	pheader.source = source;
	pheader.destination = dest;
	pheader.zero = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.length = htons(length);

	uint32_t sum = one_sum((uint8_t*)&pheader, sizeof(pheader));
	sum += one_sum(buffer, length);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)sum;
}

uint16_t TCPAssignment::one_sum(uint8_t * buffer, size_t size)
{
	bool upper = true;
	uint32_t sum = 0;
	for(size_t k=0; k<size; k++)
	{
		if(upper)
		{
			sum += buffer[k] << 8;
		}
		else
		{
			sum += buffer[k];
		}

		upper = !upper;

		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)sum;
}

}
