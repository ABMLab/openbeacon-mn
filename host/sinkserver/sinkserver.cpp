//=========================================================================
//
// File:    sinkserver.cpp
// Created: 10-27-2015, 10:12 AM
//
// Author : Mehdi Najafi
//
// Data Sink Scanner (Server Side) for BeagleBone Readers
// Copyright (C) 2015 ABMLAB @ York University
// Not premitted to be distributed and/or modified under any conditions.
//
//
// A data sink server in the internet domain using TCP
// This part runs forever, forking off a separate process for each
// connection.
//=========================================================================


#include<stdio.h>
#include<time.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<pthread.h>

#include<map>

static int quiet_flag=1;		/* Don't print out */

static FILE* logFile = NULL;
static char logfilename[1000]={"datasink.log"};

const size_t netadd_size = 10*sizeof(unsigned char);
const size_t macadd_size = 6*sizeof(unsigned char);
const size_t ipadd_size = 4*sizeof(unsigned char);

class CReaderNetAdd
{
    typedef unsigned char uchar;
    public:
        CReaderNetAdd(const uchar* _mac = NULL, const uchar* _ip = NULL)
        {
            data = new uchar[10];
            if(_mac==NULL)
                memset(data,0,netadd_size);
            else
            {
                memcpy(data,_mac,macadd_size);
                memcpy(data+6,_ip,ipadd_size);
            }
        }
        CReaderNetAdd(const CReaderNetAdd& other)
        {
            data = new uchar[10];
            memcpy(data,other.data,10*sizeof(uchar));
        }
        ~CReaderNetAdd() {delete[] data;}
        uchar* mac () const {return data;}
        uchar* ip () const {return data+6;}
        uchar operator[] (int index) const {return data[index];}
        int operator == (const CReaderNetAdd& p) {return memcmp(data,p.data,netadd_size)==0;}
        int operator != (const CReaderNetAdd& p) {return memcmp(data,p.data,netadd_size)!=0;}
        operator uchar*() {return data;}
    protected:
        unsigned char *data;
};

// map <id,mac>
static std::map<int,CReaderNetAdd*> g_readers_map;
static pthread_mutex_t g_map_lock;

int AddReader(unsigned char *_mac, unsigned char *_ip, int& id)
{
    int i;
    CReaderNetAdd p(_mac,_ip);
    std::map<int,CReaderNetAdd*>::iterator it;
    for(it = g_readers_map.begin(); it!=g_readers_map.end(); it++)
    {
        if (p==*(it->second)) {id = it->first; return 2;}
        if (memcmp(p.mac(),it->second->mac(), macadd_size)==0) {id = it->first; return 1;}
    }
    id=g_readers_map.size()+1;
    g_readers_map[id] = new CReaderNetAdd(p);
    return 0;
}


void fprintPt(FILE *fp, pthread_t pt) {
  unsigned char *ptc = (unsigned char*)(void*)(&pt);
  fprintf(fp, "0x");
  for (size_t i=0; i<sizeof(pt); i++) {
    fprintf(fp, "%02x", (unsigned)(ptc[i]));
  }
}



/*the thread function declaration*/
void *connection_handler(void *);

int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c;
    int *new_client_sock;
    struct sockaddr_in server , client;

    if (pthread_mutex_init(&g_map_lock, NULL) != 0)
    {
        printf("\nSystem Error: pthread_mutex_init failed.\n");
        return 1;
    }

    if(argc>1)
        strcpy(logfilename,argv[1]);

    /*Create socket*/
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
        return 1;
    }
    if (quiet_flag==0) printf("Socket created.\n");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 7891 );

    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    if (quiet_flag==0) printf("bind done.\n");

    //Listen
    listen(socket_desc , 30);

    //Accept and incoming connection
    if (quiet_flag==0) printf("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
	pthread_t thread_id;

    time_t mytime = time(NULL);
    //if (quiet_flag==0)
    printf("\n\n%s", ctime(&mytime));
    printf("\n S: 1-newly connected, 2-reconnected with new ip, 3-still connected.\n");
    printf(" -------------------------+----+---+-------------------+------------------\n");
    printf("        date & time       | id | S |        MAC        |         IP\n");
    printf(" -------------------------+----+---+-------------------+------------------\n");

    logFile = fopen(logfilename,"a");
    fprintf(logFile, "\n\n%s", ctime(&mytime));
    fprintf(logFile, "\n S: 1-newly connected, 2-reconnected with new ip, 3-still connected.\n");
    fprintf(logFile, " -------------------------+----+---+-------------------+------------------\n");
    fprintf(logFile, "        date & time       | id | S |        MAC        |         IP\n");
    fprintf(logFile, " -------------------------+----+---+-------------------+------------------\n");
    fclose(logFile);

    while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        if (quiet_flag==0) printf("Connection accepted.\n");

        new_client_sock = (int*)malloc(sizeof(int));
        *new_client_sock = client_sock;

        if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) new_client_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }

        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( thread_id , NULL);
        if (quiet_flag==0) {printf("\nHandler assigned:"); fprintPt(stdout, thread_id);}
    }

    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }

    return 0;
}

/*
 * This will handle connection for each client
 * */
void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int id, ret;
	char buffer[256];
	unsigned char mac[6], ipbytes[4];
    int sock = *(int*)socket_desc;
    free(socket_desc);
    pthread_detach(pthread_self());
	bzero(buffer,256);
	if ( read(sock,buffer,36) != 36 )
		{ if (quiet_flag==0) printf("L%d: ERROR reading from socket", __LINE__); return 0;}
	if (memcmp(buffer,"c67e7c76-1104-4afd-ab97-2b714a1bfd6a",36) != 0) return 0;
	//printf("L%d: received a message[%d] ... %s waiting for further ... ",__LINE__, strlen(buffer), buffer);
	if (read(sock,(char*)mac,6) != 6)
		{if (quiet_flag==0) printf("L%d: ERROR reading from socket", __LINE__); return 0;}
	if (read(sock,(char*)ipbytes,4) != 4)
		{if (quiet_flag==0) printf("L%d: ERROR reading from socket", __LINE__); return 0;}
	if (write(sock,"7784c4d9-b39f-4f7b-81c9-8b1fc30fa342",36) != 36)
		{if (quiet_flag==0) printf("L%d: ERROR writing to socket", __LINE__); return 0;}


    pthread_mutex_lock(&g_map_lock);


    ret = AddReader(mac, ipbytes, id);

    time_t mytime = time(NULL);
    sprintf(buffer,"%s",ctime(&mytime));
    buffer[strlen(buffer)-1]='\0';
//    if (quiet_flag==0)
        printf(" %s | %2d | %d | %.2x:%.2x:%.2x:%.2x:%.2x:%.2x |  %d.%d.%d.%d\n" ,
            buffer, id, ret,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]);

        logFile = fopen(logfilename,"a");
        fprintf(logFile, " %s | %2d | %d | %.2x:%.2x:%.2x:%.2x:%.2x:%.2x |  %d.%d.%d.%d\n" ,
            buffer, id, ret,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]);
        fclose(logFile);


    pthread_mutex_unlock(&g_map_lock);

        //fflush(stdout);
    return NULL;
}
