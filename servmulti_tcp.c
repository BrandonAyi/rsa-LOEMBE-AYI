/*********************************************************************
 *                                                                   *
 * FICHIER: SERVER_TCP                                               *
 *                                                                   *
 * DESCRIPTION: Utilisation de TCP socket par une application serveur*
 *              application client                                   *
 *                                                                   *
 * principaux appels (du point de vue serveur) pour un protocole     *
 * oriente connexion:                                                *
 *     socket()                                                      *
 *                                                                   * 
 *     bind()                                                        *
 *                                                                   * 
 *     listen()                                                      *
 *                                                                   *
 *     accept()                                                      *
 *                                                                   *
 *     read()                                                        *
 *                                                                   *
 *     write()                                                       *
 *                                                                   *
 *********************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define BUFSIZE 1500
int str_echo (int sockfd)
{
  int nrcv, nsnd;
  char msg[BUFSIZE];

  /*    * Attendre  le message envoye par le client 
   */
  memset( (char*) msg, 0, sizeof(msg) );
  if ( (nrcv= read ( sockfd, msg, sizeof(msg)-1) ) < 0 )  {
    perror ("servmulti : : readn error on socket");
    exit (1);
  }
  msg[nrcv]='\0';
  printf ("servmulti :message recu=%s du processus %d nrcv = %d \n",msg,getpid(), nrcv);

  if ( (nsnd = write (sockfd, msg, nrcv) ) <0 ) {
    printf ("servmulti : writen error on socket");
    exit (1);
  }
  printf ("nsnd = %d \n", nsnd);
  return (nsnd);
} /* end of function */


usage(){
  printf("usage : servmulti numero_port_serveur\n");
}


int main (int argc,char *argv[])

{
  int sockfd, n, newsockfd, childpid, servlen,fin;
  struct sockaddr_in  serv_addr, cli_addr;
  socklen_t clilen;
  int  tab_clients[FD_SETSIZE]; /*tableau des descripteurs des clients connectés*/
  fd_set rset, pset;
  int maxfdp1, nbfd, i, sockcli;

 /* Verifier le nombre de paramètre en entrée */
  if (argc != 2){
    usage();
    exit(1);}


/*
 * Ouvrir une socket (a TCP socket)
 */
if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) <0) {
   perror("servmulti : Probleme socket\n");
   exit (2);
 }

 
/*
 * Lier l'adresse  locale à la socket
 */
 memset( (char*) &serv_addr,0, sizeof(serv_addr) );
 serv_addr.sin_family = PF_INET;
 serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
 serv_addr.sin_port = htons(atoi(argv[1]));
 
 
 if (bind(sockfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr) ) <0) {
   perror ("servmulti : erreur bind\n");
   exit (1);
 }

/* Paramètrer le nombre de connexion "pending" */
 if (listen(sockfd, SOMAXCONN) <0) {
   perror ("servmulti : erreur listen\n");
   exit (1);
 }

//Initialisation
 maxfdp1 = 10;
 for (i=0; i< FD_SETSIZE; i++) tab_clients[i]=-1;
 FD_ZERO(&rset);
 FD_ZERO(&pset);
 FD_SET(sockfd,&rset);

 for (;;) {
   
   pset=rset; // ou FD_COPY(&rset,&pset)
   nbfd = select(maxfdp1, &pset, NULL, NULL,NULL);
   if (FD_ISSET(sockfd, &pset)) {
   //Une demande de connexion a été émise par un client
   	clilen = sizeof(cli_addr);
   	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr,  &clilen);
   	if (newsockfd < 0) {
    	perror("servmulti : erreur accept\n");
    	exit (1);
   	}	
	//Recherche d'une place libre dans le tableau
	i=0;
	while ((i< FD_SETSIZE) && (tab_clients[i] >= 0)) i++;
	if (i == FD_SETSIZE) exit(1);
	//Ajout du nouveau client dans le tableau des clients
	tab_clients[i]=newsockfd;
	//Ajout du nouveau client dans rset
	FD_SET(newsockfd,&rset);
	//Positionner maxfdp1
	if (newsockfd >= maxfdp1) maxfdp1=newsockfd+1;
	nbfd--;
  }
  
  //Parcourir le tableau des clients connectés
  i=0;
  while ((nbfd >0) && (i< FD_SETSIZE)) {
	if (((sockcli = tab_clients[i]) >= 0) && (FD_ISSET(sockcli,&pset))) {
		if (str_echo(sockcli)==0) {
			close(sockcli);
			tab_clients[i]=-1;
			FD_CLR(sockcli,&rset);
		}
		nbfd--;
  	}
        i++;   
  }  
 }
}



















