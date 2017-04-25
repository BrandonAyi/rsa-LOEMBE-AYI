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
#define PACKAGE_LENGTH 4096
#define HTTP_PORT 80

char *strReplace(char *orig, char *rep, char *with) { // fonction pour remplacer un char* par un autre (Source : http://stackoverflow.com/questions/779875/what-is-the-function-to-replace-string-in-c)
    char *result;
    char *ins;    
    char *tmp;    
    int len_rep;  
    int len_with; 
    int len_front; 
    int count;

    if (!orig)
      return NULL;
    if (!rep)
      rep = "";
    len_rep = strlen(rep);
    if (!with)
      with = "";
    len_with = strlen(with);

    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
      ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
      return NULL;

    while (count--) {
      ins = strstr(orig, rep);
      len_front = ins - orig;
      tmp = strncpy(tmp, orig, len_front) + len_front;
      tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
      }
      strcpy(tmp, orig);
      return result;
    }

int init(int sock, struct sockaddr_in serv_addr, int port) {

	printf("\n\n- - - - - - - - - - - - - - - - - - - - - - -");
	printf("\n- - - - - - - - PROXY SERVER BY - - - - - - - -");
	printf("\n- - - - - - - - - ALEX-KEVIN - - - - - - - - -");
	printf("\n- - - - - - - - - - - AND - - - - - - - - - - -");
	printf("\n- - - - - - - - - - BRANDON - - - - - - - - - -");
	printf("\n- - - - - - - - - NOW RUNNING - - - - - - - - - ");
	printf("\n- - - - - - - - - - - - - - - - - - - - - - - -\n\n");


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

void sendBrowser(int sockServer, char *buffer, int sockClient, int n){

  if(send(sockServer,buffer,strlen(buffer),0)<0){ //envoie le buffer au server
    perror("send()");
  }else{
    do
    {
      bzero((char*)buffer,sizeof(buffer));
      n=recv(sockServer,buffer,sizeof(buffer),0); //reçoit le buffer du server
      if(!(n<=0))
      send(sockClient,buffer,n,0); //envoie le buffer au navigateur
     } while(n>0);
  }
}

static int getBlackList(char* host, char* path) {
	FILE *fp;
	char buff[255];
	char temp[255];
	fp = fopen("black_list.txt", "r");
	while ( fgets(buff, 255, (FILE*)fp) != NULL) {
		//printf("STRSTR : %s\n", strstr(buff,"||"));
		if( strstr(buff,"||")!=NULL || strstr(buff,"##") || strstr(buff,"###") ) { 
	    	if (strstr(buff,host)!= NULL) {
	    		fclose(fp);
	    		return 0;
	    	}
	    }
	    if (path!=NULL) {
	    	strcpy(temp,path);
	    	//printf("TEMP : %s\n BUFF : %s\n\n\n",temp, buff);
		    if (strstr(temp, buff)!=NULL) {
		    	fclose(fp);
		    	return 0;
		    }
	    }
	}
	fclose(fp);
	return 1;
}

static char* getPath(char* t1, char* temp, char* path, int path_len) {
	
	strcat(t1,"^]");
	temp=strtok(t1,"//");
	temp=strtok(NULL,"/");
	temp=strtok(NULL,"^]");

  	if(temp!=NULL) { // Il faut ajouter un '/' avant le path car il est retiré par le parse de la requête
    	path_len = strlen(temp) + 2;
  		path = (char*)malloc(path_len * sizeof(char));
  		*path = '/';
  		strcat(path, temp);
	} 
	return path;
}

int main(int argc, char *argv[]) {

/*DECLARATION DE VARIABLES*/
	struct addrinfo *res, *p;
	void *addr=NULL;
	int clilen, status=0;

	int proxySocket=0, clientSocket=0; // les 2 premières socket correspondant au navigateur et au serveur dans le proxy
  	int port;
  	struct sockaddr_in clie_addr, serv_addr;

  	pid_t pid;
	char ipstr4[INET_ADDRSTRLEN], ipstr6 [INET6_ADDRSTRLEN], ipver;  //ipstr4 = addresse ipv4 et ipstr6 = addresse ipv6

  	memset((char *) &serv_addr, 0, sizeof(serv_addr));
  	memset((char *) &clie_addr, 0, sizeof(clie_addr));

  	if (argc != 2){
    	perror("erreur nombre d'argument\n");
    	exit(1);
	}

	port = atoi(argv[1]); //converti l'argument du port en int 
  	proxySocket=init(proxySocket,serv_addr, port); // initialisation de la socket proxy
  	clilen=sizeof(clie_addr);

  	for(;;) {

	  	clientSocket = accept(proxySocket,(struct sockaddr *) &clie_addr, (socklen_t *)&clilen); //socket de dialogue
		
		if(clientSocket <0){
			perror("servecho : error accept \n");
			exit(1);
		}

		pid=fork(); //fork utilisé pour le multiclient
    	if (pid==0) {

			int n=0;
		  	int sockfd=0, newsockfd=0; //créé nos deux autres sockets serveur et client
		  	int port = 80;
		  	int path_len=0;

			size_t addr_ipv6; //taille du type Ipv6

			char sendbuf[PACKAGE_LENGTH], t1[300],t2[200],t3[10];
			char *bufferCli=NULL; 
			char *path=NULL;  //path de chaque url d'une requête
			char *temp=NULL;
			char *newBuf=NULL; 
			char url[500]; //char qui va contenir l'url totale de la requête
			
			/* sockaddr IPv6 & IPv4 */
			struct sockaddr_in6 *ipv6; 
			struct sockaddr_in *ipv4;
			struct addrinfo proxy_addr;

			memset(&ipv6, 0, sizeof(ipv6));
			memset(&ipv4, 0, sizeof(ipv4));
			memset((char *) sendbuf, 0, sizeof(sendbuf));

			if ( (n=recv(clientSocket,sendbuf,sizeof(sendbuf),0 ))<0 )  { //reçoit le buffer du client par notre proxy
				perror ("error receive \n");
				exit (1);
			}

			sscanf(sendbuf,"%s %s %s",t1,t2,t3); //parsing de la requête GET
    		strcpy(url,t2); 

    		//printf(" ---T2--- : %s\n", t2);
		 
		    if(((strncmp(t3,"HTTP/1.1",8)==0)||(strncmp(t3,"HTTP/1.0",8)==0))&&((strncmp(t2,"http://",7)==0))) //traiter la requête GET (ipv4 ou ipv6)
		    {
				strcpy(t1,t2);
				temp=strtok(t2,"//");

				port=80;
				temp=strtok(NULL,"/");

				sprintf(t2,"%s",temp);
				//printf("T2 (2) : %s\n", t2); 

				path=getPath(t1, temp, path, path_len);

				memset(&proxy_addr, 0, sizeof(proxy_addr));
		  		proxy_addr.ai_family=AF_INET;
		    	proxy_addr.ai_socktype = SOCK_STREAM;

		    	//printf("PATH %s\n", path);
				if (getBlackList(t2, path) != 0) {

					if ((status = getaddrinfo(t2,NULL, &proxy_addr, &res)) != 0) { 
						fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
						exit(EXIT_FAILURE);
					}

					p=res;
					while(p!=NULL){
					// Identification de l'adresse courante
						if (p->ai_family == AF_INET) { //domaine internet ipv4
							ipv4 = (struct sockaddr_in *)p->ai_addr; //IPv4 addr
							ipv4->sin_family=AF_INET; //domaine internet ipv4
							if(port==80){
								ipv4-> sin_port = htons(HTTP_PORT); //port HTTP
							}
							addr = &(ipv4->sin_addr);
							ipver = '4'; 
							inet_ntop(p->ai_family, addr, ipstr4, INET_ADDRSTRLEN); // transforme l'adresse Ip en char

						}else { // IPv6
							ipv6 = (struct sockaddr_in6 *)p->ai_addr; 
							ipv6->sin6_family=AF_INET6; // //domaine internet ipv6
							ipv6-> sin6_port = htons(HTTP_PORT);
							addr = &(ipv6->sin6_addr); // IPv6 addr
							addr_ipv6 = p-> ai_addrlen; //different type of sock-addr so different length for the connect argument
							ipver = '6';
							inet_ntop(p->ai_family, addr, ipstr6, INET6_ADDRSTRLEN);
						}

						p = p->ai_next; //Prochaine adresse
					}

					if (ipv6!=NULL){ //Soit c'est du ipv6
						if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) <0) { //création de la socket pour Ipv6
							perror ("error with the proxy\n");
							exit (1);
						}
						if((newsockfd=connect(sockfd,(struct sockaddr *)ipv6, addr_ipv6))<0){ //connexion entre client et serveur
							perror("connect()");
						}

					} else { //Sinon c'est du ipv4
						if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) <0) { //création de la socket pour Ipv4
							perror ("error with the proxy\n");
							exit (1);
						}
						if((newsockfd=connect(sockfd,(struct sockaddr*)ipv4,sizeof(struct sockaddr)))<0){ //connexion entre client et serveur
							perror("connect()");
						}
					}

					if((temp!=NULL) || (port ==80)){  //If we are in HTTP

						if(path==NULL){  // Il faut quand même un '/' même si le buffer est nul
							path="/";
						}

						newBuf = strReplace(sendbuf,url, path); // replace the url send by the path

						bufferCli = strReplace(newBuf, "keep-alive", "close"); // remplace keep alive par close 
						
						strcat(bufferCli, "Connection: close");  // prepare le buffer à être envoyer

						sendBrowser(sockfd, bufferCli, clientSocket, n); // envoie le buffer au navigateur

					}
				} else {printf("SITE BLACKLISTE\n");} 
			}

			close(sockfd);  //close our sockets
			close(clientSocket);
			close(proxySocket);
			exit(0);

		} else {
	    	close(clientSocket);
	  	}
  	}
  	return 0;
}
