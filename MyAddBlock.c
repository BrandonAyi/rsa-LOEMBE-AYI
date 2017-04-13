#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#define SERV_PORT 2222
#define PACKAGE_LENGTH 4096 // be careful, if you increase the buffer's size, you won't receive packets from the browser
#define HTTP_PORT 80

int init(int sock, struct sockaddr_in serv_addr, int port) {

	serv_addr.sin_family = AF_INET ;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	/*
	   * Ouvrir socket (socket STREAM)
	   */
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) <0) {
	    perror ("erreur socket");
	    exit (1);
	}

	/*
	  * Lier l'adresse locale à la socket
	  */
	if(bind(sock,(struct sockaddr *)&serv_addr, sizeof (serv_addr) ) <0) {
	   perror ("servecho: erreur bind\n");
	   exit (1);
	  }

	/* Paramètrer le nombre de connexion "pending" */
	 if (listen(sock, SOMAXCONN) <0) {
	   perror ("servmulti : erreur listen\n");
	   exit (1);
	 }

	 return sock;
}

void envoyerAuNavigateur(int sockServer, char *buffer, int sockClient, int n){

  n=send(sockServer,buffer,strlen(buffer),0);  //envoie le buffer au server
  if(n<0){
    perror("send()");
  }else{
    do
    {
      bzero((char*)buffer,sizeof(buffer));
      n=recv(sockServer,buffer,sizeof(buffer),0); //reçoit le buffer du server
      if(!(n<=0))
      send(sockClient,buffer,n,0);  //envoie le buffer au navigateur
     }while(n>0);
  }
}

int main(int argc, char *argv[]) {

	int proxySocket=0, clientSocket=0; // les 2 premières socket correspondant au navigateur et au serveur dans le proxy
  	struct sockaddr_in clie_addr, serv_addr;
  	int port;
  	int clilen;

	struct addrinfo *res, *p;
	void *addr=NULL;
	int status=0; 
	char ipstr4[INET_ADDRSTRLEN], ipver;  //ipstr4 = address ipv4 and ipstr6 = address ipv6
	char ipstr6 [INET6_ADDRSTRLEN];

  	memset((char *) &serv_addr, 0, sizeof(serv_addr));
  	memset((char *) &clie_addr, 0, sizeof(clie_addr));

  	port = atoi(argv[1]); //converti l'argument du port en int

  	if (argc != 2){
    	perror("erreur nombre d'argument\n");
    	exit(1);
	}
  	proxySocket=init(proxySocket,serv_addr, port); // initialisation de la socket proxy
  	clilen=sizeof(clie_addr);

  	clientSocket = accept(proxySocket,(struct sockaddr *) &clie_addr, (socklen_t *)&clilen);
	if(clientSocket <0){
		perror("servecho : erreur accept \n");
		exit(1);
	}

	/*Pour un seul client */
	int n=0;
  	int sockfd=0, newsockfd=0; //create our two other socket which is server and client sight of the proxy sockets
  	int path_len;

	size_t addr_ipv6; //length type for IPv6

	char sendbuf[PACKAGE_LENGTH], t1[300],t2[200],t3[10];
	char *bufferCli=NULL; 
	char *path=NULL;  //path of each url of a request
	char *temp=NULL;
	char *newBuf=NULL; 
	char url[500]; //char qui va contenir l'url totale de la requête
	struct sockaddr_in6 *ipv6; 
	struct sockaddr_in *ipv4;
	struct addrinfo proxy_addr;

	memset(&ipv6, 0, sizeof(ipv6));
	memset(&ipv4, 0, sizeof(ipv4));
	memset((char *) sendbuf, 0, sizeof(sendbuf));


	if ( (n= recv(clientSocket,sendbuf,sizeof(sendbuf),0 ))<0 )  { //function recv that receives the buffer of the client by our proxy
		perror ("erreur receive \n");
		exit (1);
	}

	//-------------------PARTIE A ANALYSER ----------------------

	/*
	sscanf(sendbuf,"%s %s %s",t1,t2,t3); //Parsing the request GET 
    strcpy(url,t2); 
    
    if(((strncmp(t3,"HTTP/1.1",8)==0)||(strncmp(t3,"HTTP/1.0",8)==0))&&((strncmp(t2,"http://",7)==0))) //Treats the request GET and POST in ipv4 or ipv6
    {
      strcpy(t1,t2);
      temp=strtok(t2,"//");
      port=80;
      temp=strtok(NULL,"/");
      
      sprintf(t2,"%s",temp);

      strcat(t1,"^]");
      temp=strtok(t1,"//");
      temp=strtok(NULL,"/");
      temp=strtok(NULL,"^]");

      if(temp!=NULL) { // We need to add a '/' before our path because the parse of the request delete it
        path_len = strlen(temp) + 2;
      path = (char*)malloc(path_len * sizeof(char));
      *path = '/';
      strcat(path, temp); 
    } 

	memset(&proxy_addr, 0, sizeof(proxy_addr));
  	proxy_addr.ai_family=AF_INET;
    proxy_addr.ai_socktype = SOCK_STREAM; 

	if ((status = getaddrinfo(t2,NULL, &proxy_addr, &res)) != 0) { 
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 2;
	}

	p=res;
	while(p!=NULL){
	// Identification de l'adresse courante
		if (p->ai_family == AF_INET) { // IPv4
			ipv4 = (struct sockaddr_in *)p->ai_addr; //IPv4 addr
			ipv4->sin_family=AF_INET; //IPv4 family
			if(port==80){
				ipv4-> sin_port = htons(HTTP_PORT); //port HTTP
			}
			addr = &(ipv4->sin_addr);
			ipver = '4'; 
			inet_ntop(p->ai_family, addr, ipstr4, INET_ADDRSTRLEN); // transform the ip adress into char

		}else { // IPv6
			ipv6 = (struct sockaddr_in6 *)p->ai_addr; //

			ipv6->sin6_family=AF_INET6; // IPv6 family
			ipv6-> sin6_port = htons(HTTP_PORT); //HTTP port
			addr = &(ipv6->sin6_addr); // IPv6 addr
			addr_ipv6 = p-> ai_addrlen; //different type of sock-addr so different length for the connect argument
			ipver = '6';
			inet_ntop(p->ai_family, addr, ipstr6, INET6_ADDRSTRLEN); // transform the ip adress into a char 
		}

		p = p->ai_next;
	}


	if (ipv6!=NULL){
		if (argv[2]!=NULL && (strncmp(argv[2], "-p", 2)==0)){
			printf(" IPv6: %s\n", ipstr6);
		}
		if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) <0) { // create our socket for IPv6
			perror ("ERROR WITH THIS PROXY\n");
			exit (1);
		}
		if((newsockfd=connect(sockfd,(struct sockaddr *)ipv6, addr_ipv6))<0){ //  connect between client sight and server socket 
			perror("connect()");
		}


	} else {
		if (argv[2]!=NULL && (strncmp(argv[2], "-p", 2)==0)){
			printf(" IPv4: %s\n", ipstr4);
		}
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) <0) { //create our socket for IPv4
			perror ("ERROR WITH THIS PROXY\n");
			exit (1);
		}
		if((newsockfd=connect(sockfd,(struct sockaddr*)ipv4,sizeof(struct sockaddr)))<0){ //  connect between client sight and server socket
			perror("connect()");
		}
	}

	if((temp!=NULL) || (port ==80)){  //If we are in HTTP

		if(path==NULL){  // If the path is null the buffer still anyway want to have a '/'
			path="/";
		}

		newBuf = strReplace(sendbuf,url, path); // replace the url send by the path

		bufferCli = strReplace(newBuf, "keep-alive", "close"); // replace keep alive by close 

		strcat(bufferCli, "Connection: close");  // prepare our buffer to be send

		if (argv[2]!=NULL && (strncmp(argv[2], "-p", 2)==0)){
			printf("HOSTNAME =%s\n", t2);
			printf("SEND BUFFER : \n%s\n", bufferCli);
		}

		envoyerAuNavigateur(sockfd, bufferCli, clientSocket, n); // function that send the buffer to the browser


	}
	}
	close(sockfd);  //close our sockets
	close(clientSocket);
	close(proxySocket);
	exit(0);  */
 
}