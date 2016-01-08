#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
//#include <limits.h> //for using macro INT_MAX
#include <netdb.h> //for gethostbyname()
#include <arpa/inet.h>
#include <pthread.h>

int **graph; 
typedef struct 
{
	char *destination;
	char *nextHop;
	int cost;
	unsigned short int ttl;
}routeEntry;

routeEntry* routingTable;

typedef struct
{
	char *address;
	char isNeighbor;//'y' - Yes, 'n' - No, 'd' - Dead, 'i' - this node
	char label;
}hop;

hop* allNodesInfo;

typedef struct
{
        char address[100];
	int cost;
}msg;

typedef struct
{
	int fd;//File descriptor of socket
	int size;//Number of nodes in the network
	unsigned short defaultTTL;//Send Default TTL
	int splitH;//Send SplitHorizon
	int portN;//Send portNumber
	int period;//Send period
	int infinity; //Send infinity
	//int **graph;//Send Graph
}threadVar;

pthread_mutex_t lock;

//TIME CHECK PURPOSE
void timer()
{
        static int flag = 0;
	static double start = 0.0f, end = 0.0f;
	struct timeval t;
        int left_part, right_part;
        char buf[50];
	gettimeofday(&t, NULL);
        if(!flag)
        {
                //printf("FLAG = 0\n");
		start = t.tv_sec + (t.tv_usec/1000000.0);
		//printf("START =%ld, END = %ld\n", start, end);
                flag = 1;
        }
        else
        {
                //printf("FLAG = 1\n");
		end = t.tv_sec + (t.tv_usec/100000.0);
		//printf("START = %ld, END = %ld\n", start, end);
                end -= start;
		//printf("START =%ld, END = %ld\n", start, end);

                sprintf(buf, "%lf", end);
                sscanf(buf, "%d.%d", &left_part, &right_part);
		printf("Time: %d sec %d usec\n\n", left_part, right_part);
        }
}

void error(const char *msg)
{
	perror(msg);
	//printf("%s\n", msg);
	exit(1);
}

void initializeThread()
{
	pthread_mutex_init(&lock, NULL);
}

int countLines(char config[])
{
	int count = 0;
	char c;
	FILE *fp = fopen(config, "r");
	while((c = getc(fp))!=EOF)
	{
		if(c == '\n')
			++count;
	}
	fclose(fp);
	//printf("IN COUNTLINES COUNT =%d\n", count);
	return count;
}

void displayGraph(int size)
{
	int i, j;
	printf("Graph:\n\t\t\t\t");
	for(i=0; i < size; ++i)
	{
		printf("\t%c", allNodesInfo[i].label);
	}
	printf("\n");
	for (i = 0; i < size; i++)
	{	
		printf("%-30s\t%c\t",allNodesInfo[i].address, allNodesInfo[i].label);
		for (j = 0; j < size; j++)
			printf("%d\t", graph[i][j]);
		printf("\n");
	}

	printf("\n");
}

void displayRoutingTable(int size)
{
	int i;
	printf("Routing Table:\nTo\t\t\t\tNext Hop\t\t\tCost\tTTL\n");
	for(i = 0; i < size; ++i)
		printf("%-30s\t%-30s\t%-4d\t%-4d\n",routingTable[i].destination, routingTable[i].nextHop, routingTable[i].cost, routingTable[i].ttl);
	printf("\n");

}

void itoa(long a, char noToStr[])
{
	sprintf(noToStr, "%ld", a);
}

int checkPageExists(char *page)
{
	if((access(page, F_OK))==-1)
		return -1; // Does not exist
	return 0;//Exists
}

void allocateSize(int size)
{
	int i;
	graph = (int **)malloc(size * sizeof(int *));
	for (i=0; i<size; i++)
	       	graph[i] = (int *)malloc(size * sizeof(int));
	routingTable = (routeEntry *)malloc(size * sizeof(routeEntry));
	allNodesInfo = (hop *)malloc(size * sizeof(hop));
	//printf("LEAVING ALLOCATESIZE\n");
}

void displayMyView(int l)
{	
	int i;
	for(i=0;i<l;++i)
        {
                printf("i=%d \t%c \t%s \t%c \n",i,allNodesInfo[i].label, allNodesInfo[i].address, allNodesInfo[i].isNeighbor);
        }
	
}

void parseConfig(char *page, int lineCount, char *thisNodeIP)
{
	FILE *fp = fopen(page, "r");
	char ch, node[50];
	int i, index = 0, labelValue = 65, counter = 0;
	allNodesInfo[index].address = (char *)malloc(sizeof(char)* (strlen(thisNodeIP) + 1));
	strcpy(allNodesInfo[index].address, thisNodeIP);
	allNodesInfo[index].label = labelValue++;
	allNodesInfo[index++].isNeighbor = 'i';
	//printf("BEFORE WHILE LINECOUNT = %d\n", lineCount);

	while(lineCount != 0)
	{
		do
		{
			node[counter++] = getc(fp);
		}while(node[counter-1] != ' ');
		//printf("AFTER DO WHILE\n");
		if(node[counter-1]== ' ')
		{
			node[--counter] = '\0';
			ch = getc(fp);
			//printf("NODE = %s\t%d\n", node, strlen(node));
			allNodesInfo[index].address = (char *)malloc(sizeof(char)* (strlen(node)+1));
			strcpy(allNodesInfo[index].address, node);
			allNodesInfo[index].label = labelValue++;
			//printf("DEBUG: %c \t%s \t\n",allNodesInfo[index].label, allNodesInfo[index].address);
			if(ch == 'y' || ch =='Y')
			{
				//printf("FOUND +YES\n");
				//Found Yes - Is a neighbor
				allNodesInfo[index].isNeighbor = 'y';
				for(i=1; i < 4; ++i)
                                	getc(fp);

			}	
			else if(ch == 'n' || ch == 'N')
			{
				//printf("FOUND + NO\n");
				//Found No
				allNodesInfo[index].isNeighbor = 'n';
				for(i=1; i < 3; ++i)
					getc(fp);
			}
		}
		counter = 0;
		++index;
		bzero(node, sizeof(node));
		--lineCount;
		//printf("i=%d \t%c \t%s \t%c \n",index-1,allNodesInfo[index-1].label, allNodesInfo[index-1].address, allNodesInfo[index-1].isNeighbor);
	}
	//printf("%c \t%s \t%c \n",allNodesInfo[2].label, allNodesInfo[2].address, allNodesInfo[2].isNeighbor);

	//displayMyView(8);
	fclose(fp);
}

void initializeGraph(int num)
{
	int i, j;
	for(i=0;i<num;++i)
	{	
		for(j=0; j<num; ++j)
			graph[i][j] = 9999;//INT_MAX;
	}
	for(i=0; i<num; ++i)
	{
		if(allNodesInfo[i].isNeighbor == 'i')
			graph[0][i] = 0;
		else if(allNodesInfo[i].isNeighbor == 'y')
			graph[0][i] = 1;
		else
			graph[0][i] = 9999;//INT_MAX;
	}
	//printf("INITIALIZED IN FUNCTION\n");
	displayGraph(num);
}


void initializeRoutingTable(int size, int defaultTtl)
{
	int i;
	for(i = 0; i < size; ++i)
	{
		routingTable[i].destination = (char *)malloc(sizeof(char)* (strlen(allNodesInfo[i].address) + 1));
		routingTable[i].cost = graph[0][i];
		strcpy(routingTable[i].destination, allNodesInfo[i].address);
		//if(allNodesInfo[i].isNeighbor == 'i' || allNodesInfo[i].isNeighbor == 'y')
		if(graph[0][i] < 2)
		{	
			routingTable[i].nextHop = (char *)malloc(sizeof(char)* (strlen(allNodesInfo[i].address)+1));
			strcpy(routingTable[i].nextHop, allNodesInfo[i].address);
		}
		else
		{
			routingTable[i].nextHop = (char *)malloc(sizeof(char)* 5);
			strcpy(routingTable[i].nextHop, "NULL");
		}
		routingTable[i].ttl = defaultTtl;
	}
	//displayRoutingTable(size);	
}

void initialize(int size, char *config, int ttl, int period, char *thisNodeIP)
{
	//printf("IN INITIALIZE\n");
	allocateSize(size);
	//printf("AFTER CALL TO ALLOCATESIZE\n");
	parseConfig(config, size - 1, thisNodeIP);
	//printf("AFTER CALL TO PARSECONFIG\n");
	initializeGraph(size);
	//printf("AFTER CALL TO INITIALIZEGRAPH\n");
	initializeRoutingTable(size, ttl);
	//printf("AFTER CALL TO INITIALIZEROUTINGTABLE\n");
	displayRoutingTable(size);
	
	//makeRoutingTable(size + 1, ttl);
	//displayMyView(size+1);
}

void ipToHostname(struct sockaddr_in ipAddress, char *hostName)
{
	//struct hostent *ip;
	//ip = gethostbyaddr(&ipAddress, sizeof(ipAddress), AF_INET);
	char service[20];
	getnameinfo((struct sockaddr*)&ipAddress, sizeof(ipAddress), hostName, 100, service, 20, 0);
	//strcpy(hostName, ip -> h_name);
	//printf("IN FUNCTION IPTOHOSTNAME HOSTNAME = %s\nSERVICE: %s", hostName, service);
}

struct sockaddr_in hostnameToIp(char *hostName, int portNo)
{
	struct hostent *ip;
	struct in_addr **addr_list;
	int i;
	struct sockaddr_in nodeAddr;
	ip = gethostbyname(hostName);
	//printf("SIZEOF INT=%d\n", sizeof(int));
        if (ip == NULL)
        {
        	printf("%s\n", hostName);
		error("ERROR: Host given in config file, was not found. \nDid the execution return from gethostname function");
	}
        bzero((char *)&nodeAddr, sizeof(nodeAddr));
        nodeAddr.sin_family = AF_INET;
        bcopy((char *)ip->h_addr,
         (char *)&nodeAddr.sin_addr.s_addr,
         ip->h_length);
        nodeAddr.sin_port = htons(portNo);

	return nodeAddr;
}

void serialize(char *buffer, msg *messages, int size)
{
	int i, j, counter;
	uint32_t co;
	char ip[100];	
	for(i=0; i<size; ++i)
	{
		bzero(ip, 100);
		strcpy(ip, messages[i].address);
		co = messages[i].cost;
		counter = 0;
		for(j = i*104; counter < 100; ++j, ++counter)
		{
			buffer[j] = ip[counter];
		}
		buffer[j] = co >> 24;
		buffer[j+1] = co >> 16;
		buffer[j+2] = co >> 8;
		buffer[j+3] = co;
	}
	/*
	printf("SERIALIZED:\n");
	for(i = 0; i<(size*104);++i)
		printf("%c", buffer[i]);
	printf("\n");
	*/
}

void deserialize(char *buffer, msg *messages, int size)
{
	int i, j, counter;
	uint32_t co;
        char ip[100];
	//printf("DE-SERIALIZED:\n");
        for(i=0; i<size; ++i)
        {
		counter = 0;
		co = 0;
		bzero(ip, 100);
                for(j = i*104; counter < 100; ++j, ++counter)
                {
                        ip[counter] = buffer[j];
                }
		ip[99] = '\0';
		strcpy(messages[i].address, ip);
		
		co |= buffer[j] << 24;
		co |= buffer[j+1] << 16;
		co |= buffer[j+2] << 8;
		co |= buffer[j+3];
		messages[i].cost = co;
		
                //printf("IP:%s\tCOST:%d\n", messages[i].address, messages[i].cost);
        }
}

void sendOverSocket(char *to, msg *messages, int fd, int portNo, int size)
{
	//printf("In SENDOVERSOCKET\n SEND TO:%s\nPORT NO: %d\n%d\n", to, portNo, sizeof(messages));
	
	int n, nodeLen;
	struct sockaddr_in nodeAddr;
	char *dataToSend;
	dataToSend = (char *)malloc((104 * size) * sizeof(char));
	nodeAddr = hostnameToIp(to, portNo);
	//printf("1\n");
	nodeLen = sizeof(nodeAddr);
	
	serialize(dataToSend, messages, size);
	//deserialize(dataToSend, messages, size);

	if((n = sendto(fd, dataToSend, (104*size), 0, (struct sockaddr*)&nodeAddr, nodeLen)) < 0)
	{
		error("ERROR: Failed to Write to Socket\n");
	}
	free(dataToSend);
	printf("Sent Advertisement to %s\n\n",to);
}

/*
void reduceMessageSize(msg *origMessage, int size)
{
	int i;
	//msg *temp;
	msg *messageToSend = (msg *)malloc(sizeof(msg) * size);
	for(i=0; i < size; ++i)
	{
		strcpy(messageToSend[i].address, origMessage[i].address);
		messageToSend[i].cost = origMessage[i].cost;
	}
	//temp = origMessage;
	//free(temp);
	
	origMessage = messageToSend;

	//free(messageToSend);
	//return messageToSend;
}
*/
int createAdvertisement(char *neighbor, int splitHorizon, msg *messages, int num)
{
	int i, counter;
	if(!splitHorizon)
	{
		//printf("IN SPLIT\n SPLIT = %d NUM = %d\n", splitHorizon, num);
		for(i = 0; i < num; ++i)
		{
			strcpy(messages[i].address, routingTable[i].destination);
			messages[i].cost = routingTable[i].cost;
			//printf("ENTRY: %s\t %d",messages[i].address, messages[i].cost);
		}
	}
	else
	{
		counter = 0;
		for(i = 0; i < num; ++i)
		{
			//-----------------------------------------------SplitHorizon
			if(strcmp(routingTable[i].nextHop, neighbor) == 0)
				continue;
			strcpy(messages[counter].address, routingTable[i].destination);
			messages[counter].cost = routingTable[i].cost;
			++counter;
	
			/*----------------------------------SplitHorizonPoissonReverse
 			strcpy(messages[i].address, routingTable[i].destination);
			if(strcmp(routingTable[i].nextHop, neighbor) == 0)
				messages[i].cost = 9999;//INT_MAX;
			else
				messages[i].cost = routingTable[i].cost;
			*/
		}
		//printf("COUNTER = %d\n", counter);
		num = counter;
		//reduceMessageSize(messages, num);
	}
	
	printf("Advertisement Created:\n");
	for(i=0;i<num;++i)
		printf("%-30s\t %d\n",messages[i].address, messages[i].cost);

	printf("\n");
	return num;//Updated Message Size in case of Split Horizon
}

void sendAdvertisement(int splitHorizon, int num, int fd, int portNo)
{
	int i, newMsgSize;
	msg* updateMessages = (msg *)malloc(num * sizeof(msg));
	//printf("IN SENDADVERTISEMENT: num = %d\n",num);
	if(!splitHorizon)
	{
		//No Split Horizon
		//printf("IN NO SPLIT HORIZON\n");
		createAdvertisement("", 0, updateMessages, num);
		for(i=1; i < num; ++i)
                {
			if(allNodesInfo[i].isNeighbor == 'y')
                        {
				//printf("NEIGHBOR: %s\n", allNodesInfo[i].address);
				sendOverSocket(allNodesInfo[i].address, updateMessages, fd, portNo, num);
			}
		}
	}
	else
	{
		//Implementing Split Horizon
		for(i=1; i < num; ++i)
		{	
			newMsgSize = 0;
			if(allNodesInfo[i].isNeighbor == 'y')
			{
				newMsgSize = createAdvertisement(allNodesInfo[i].address, 1, updateMessages, num);
				sendOverSocket(allNodesInfo[i].address, updateMessages, fd, portNo, newMsgSize);
			}
		}
	}
	free(updateMessages);
}

void checkAndAdd(char *config)
{
	//Add \n to the end of file if it is not present
	FILE *fp = fopen(config, "a+");
	fseek(fp, -1, SEEK_END);
	if(getc(fp) != '\n')
	{
		fputs("\n\0", fp);
	}
	fclose(fp);
}

void backFromTheDead(char* node, int size, unsigned short defaultTTL)
{
	int i;
	for(i=0; i < size; ++i)
	{
		if(strcmp(node, allNodesInfo[i].address) == 0)
		{
			if(allNodesInfo[i].isNeighbor == 'n')
			{
				allNodesInfo[i].isNeighbor = 'y';
				graph[0][i] = 1;
				strcpy(routingTable[i].nextHop, node);
				routingTable[i].cost = 1;
				routingTable[i].ttl = defaultTTL;
			}
			break;
		}
	}
}

//Bellman-Ford Algorithm
int updateRoutingInfo(msg* message, int size, char *fromHost, unsigned short defaultTTL, int infinity)
{
	int i, j, index, newCost;
	int flag = 0;//Was there a change made in the routing table?
	backFromTheDead(fromHost, size, defaultTTL);
	for(i=0; i < size; ++i)
	{
		index = 0;
		newCost = 0;
		for(j=0; j<size; ++j)
			if(strcmp(routingTable[j].destination, fromHost) == 0)
				index = j;
		for(j=0; j < size; ++j)
		{	if(strcmp(message[i].address, routingTable[j].destination) == 0)
			{
				//printf("%s %s\n", message[i].address, routingTable[j].destination);
				newCost = routingTable[index].cost + message[i].cost;
				if(newCost > 9999)
					newCost = 9999;
				
 				if(newCost == infinity)
				{
					//Detected Routing Loop
					routingTable[j].cost = 9999;
					graph[0][j] = 9999;
					strcpy(routingTable[j].nextHop, "NULL");
					flag = 1;
					continue;
				}
				if(graph[0][j] > newCost || strcmp(routingTable[j].nextHop, fromHost) == 0)
				{
					if(graph[0][j] > newCost || (graph[0][j] < newCost && (strcmp(routingTable[j].nextHop, fromHost) == 0)))
					{	
						flag = 1;
					}
					graph[0][j] = newCost;
					routingTable[j].cost = newCost;
					routingTable[j].ttl = defaultTTL;
					if(!(newCost >= infinity))
						strcpy(routingTable[j].nextHop, fromHost);
					else
						strcpy(routingTable[j].nextHop, "NULL");
				}
				/*
 					if(strcmp(fromHost, routingTable[j].nextHop) == 0)
					routingTable[j].ttl = defaultTTL;
				*/
			}
		}
	}
	return flag;
}
	
void* receiverThread(void* recv)
{
	int fd, size, n, clilen, changed, i, splitHorizon, portNumber, infinity;
	struct sockaddr_in cli_addr;
	unsigned short ttl;
	threadVar *received = (threadVar *)recv;
	fd = received -> fd;
	size = received -> size;
	ttl = received -> defaultTTL;
	splitHorizon = received -> splitH;
	portNumber = received -> portN;
	infinity = received -> infinity;
	//graph = received -> graph;

	clilen = sizeof(cli_addr);
        msg *messages = (msg *)malloc(sizeof(msg) * size);
        char *receivedBuffer = (char *)malloc(104 * size);
	char fromIP[100];
        
	while(1)
        {
		changed = 0;
		bzero(receivedBuffer, (104 * size));
                n = recvfrom(fd, receivedBuffer, (104 * size), 0, (struct sockaddr*)&cli_addr, &clilen);
		if(n<0)
                        error("Server Error: In receiving from client\n");
		deserialize(receivedBuffer, messages, size);
                //printf("RECVD FROM IP = %s\n%dbytes\n",ipAddress,n);
                ipToHostname(cli_addr, fromIP);
		//printf("Received Advertisement from %s\n\n", fromIP);
		//gethostname(ipAddress, sizeof(ipAddress));
		
		//-----------------------MUTEX LOCK------------------------------
		pthread_mutex_lock(&lock);
		//printf("RECEIVER MUTEX LOCKED\n");
		changed = updateRoutingInfo(messages, size, fromIP, ttl, infinity);
		//If Routing Table Entry changed send Triggered Updates:
		if(changed)
		{	
			sendAdvertisement(splitHorizon, size, fd, portNumber);
			timer();
		}
		//printf("RECEIVER BEFORE MUTEX UNLOCK ADDRESS %u\n", &lock);
		//printf("\nTime: %d sec %d usec\n", left_part, right_part);
		pthread_mutex_unlock(&lock);
		//pthread_mutex_lock(&lock);

		//printf("RECEIVER MUTEX UNLOCKED\n");
		//pthread_mutex_unlock(&lock);

		//---------------------------------------------------------------
                
		displayGraph(size);
		displayRoutingTable(size);
        }
        
	return NULL;
}

void checkTTLUpdateNeighbor(int size, int period)
{
	int i, timeToLive;
	//i = 1 because don't have to check for myself that is node 0
	for(i=1; i <size; ++i)
	{
		timeToLive = routingTable[i].ttl;
		if(!(timeToLive <= 0))
			timeToLive -= period;
		routingTable[i].ttl = timeToLive;
		if(timeToLive <= 0)
		{
			allNodesInfo[i].isNeighbor = 'n';
			strcpy(routingTable[i].nextHop, "NULL");
			routingTable[i].cost = 9999;
			graph[0][i] = 9999;
		}
	}
}

void* senderThread(void* recv)
{
        int fd, size, n, clilen, changed, i, splitHorizon, portNumber, period;
        struct sockaddr_in cli_addr;
	unsigned short ttl;
        threadVar *received = (threadVar *)recv;
        fd = received -> fd;
        size = received -> size;
        //ttl = received -> defaultTTL;
        splitHorizon = received -> splitH;
        portNumber = received -> portN;
	period = received -> period;
	//graph = received -> graph;
	//printf("IN SENDER THREAD\n");
	
	while(1)
	{
		sleep(period);
		//printf("SENDER BEFORE MUTEX LOCK ADDRESS = %u\n", &lock);
		pthread_mutex_lock(&lock);
		//printf("SENDER MUTEX LOCKED\n");
                checkTTLUpdateNeighbor(size, period);
		sendAdvertisement(splitHorizon, size, fd, portNumber);
		timer();
		pthread_mutex_unlock(&lock);
		//printf("SENDER BEFORE MUTEX UNLOCK = %u\n", &lock);
		//printf("SENDER MUTEX UNLOCKED\n");
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int sockfd, portNumber, clilen, servlen, ttl, infinity, period, splitHorizon, noOfLines;
	char config[256];
	//struct timeval t;
	fflush(stdout);	
	struct sockaddr_in serv_addr, cli_addr;
	if (argc < 7)
	{
		fprintf(stderr,"USAGE: %s config portNumber ttl infinity period splitHorizon\n", argv[0]);
		exit(1);
    	}
	strcpy(config, argv[1]);
	
	if(checkPageExists(config) == -1)
		error("Config Page does not exist!\n");
	checkAndAdd(config);
	portNumber = atoi(argv[2]);
	ttl = atoi(argv[3]);
	infinity = atoi(argv[4]);
	period = atoi(argv[5]);
	splitHorizon = atoi(argv[6]);

	//----------------------------------------------------------SOCKET
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
		error("SERVER ERROR: Cannot create socket\n");
	servlen = sizeof(serv_addr);
	bzero((char *) &serv_addr, servlen);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portNumber);
	if (bind(sockfd, (struct sockaddr*)&serv_addr, servlen) < 0) 
		error("SERVER ERROR: Cannot Bind\n");
	//----------------------------------------------------------------
	
	char ipAddress[100];
	gethostname(ipAddress, sizeof(ipAddress));
	//printf("Server IP = %s\n",ipAddress);
	clilen = sizeof(cli_addr);
	
	noOfLines = countLines(config);
	//printf("BEFORE CALL TO INITIALIZE\n");
	initialize(noOfLines + 1, config, ttl, period, ipAddress);
	//printf("AFTER CALL TO INITIALIZE\n");
	//displayGraph(noOfLines);
	//sendAdvertisement(splitHorizon, noOfLines + 1, sockfd, portNumber);
	//printf("AFTER CALL TO SENDADVERTISEMENT\n");
	
	timer();
	initializeThread();//mutex and conditional variable

	threadVar sendToThread;
        sendToThread.fd = sockfd;
        sendToThread.size = noOfLines + 1;
        sendToThread.defaultTTL = ttl;
        sendToThread.splitH = splitHorizon;
        sendToThread.portN = portNumber;
        sendToThread.period = period;
	sendToThread.infinity = infinity;
	//sendToThread.graph = graph;
	//----------------------------Send Advertisement every period time Thread
	pthread_t sendAdThread;
        int retVal1 = 0;

        retVal1 = pthread_create(&sendAdThread, NULL, senderThread, &sendToThread);

	if(retVal1 != 0)
                error("Error: Creation of sendAdvertisement thread.\n");
	//-----------------------------------------------------------------------
	
	
	//-------------------------------------------Advertisement Receive Thread
	pthread_t recvAdThread;
	int retVal2 = 0;
	
	retVal2 = pthread_create(&recvAdThread, NULL, receiverThread, &sendToThread);
	if(retVal2 != 0)
		error("Error: Creation of receiverThread.\n");	
	//-----------------------------------------------------------------------
	
		
	/*
-----------------MOVED tO THREAD-------------------------------------------------
	int n, i;
	
	msg *messages = (msg *)malloc(sizeof(msg) * (noOfLines + 1));
	char *receivedBuffer = (char *)malloc(104 * sizeof(msg) * (noOfLines +1));
	while(1) 
	{
		n = recvfrom(sockfd, receivedBuffer, (104 * (noOfLines + 1)), 0, (struct sockaddr*)&cli_addr, &clilen);
		deserialize(receivedBuffer, messages, (noOfLines + 1));
		inet_ntop(AF_INET, &(cli_addr.sin_addr), ipAddress, INET_ADDRSTRLEN);
		printf("RECVD FROM IP = %s\n%dbytes\n",ipAddress,n);
	
		if(n<0)
			error("Server Error: In receiving from client\n");
		//buf[n]='\0';
		for(i=0; i< noOfLines + 1; ++i)
			printf("IP: %s\nCost: %d\n", messages[i].address, messages[i].cost);
	}
---------------------------------------------------------------------------------
	*/
	if(pthread_join(recvAdThread,NULL))
        {
                error("Error: In Joining Thread\n");
        }

	if(pthread_join(sendAdThread,NULL))
        {
                error("Error: In Joining Thread\n");
        }

	close(sockfd);
	free(graph);
	free(routingTable);
	free(allNodesInfo);
	//free(messages);
	//free(receivedBuffer);
	return 0; 
}
