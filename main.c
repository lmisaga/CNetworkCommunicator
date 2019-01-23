#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory.h>
#include <unistd.h>
#include <termio.h>
#define PORT 8080   //port on which the program initializes the server
#define MAXMSGLEN 100000    //maximum message length - 99.999 bytes/characters, last character is substitued by '\0'
#define FRAG_SIZE 512       //maximum message fragment size - safe UDP packet payload is <=512 bytes per packet

/**
 * @brief This program implements a simple communication tool between multiple clients and one server. It uses UDP sockets
 * to communicate between the relays. Since classic UDP packets are not reliable, various precautions are implemented to
 * further assure integrity of the sent and received data.
 */


/**
 * Custom header with data to verify the integrity of the UDP packets
 * CRC and packetNumber are used to verify the content and index of the packet
 * type represents a packet type:
 * 0 for ACK
 * 1 for packet-resend flag
 * 2 for keepalive packet (not used)
 * 3 for packet integrity error (packet cannot be verified - terminal error)
 * 4 for server-client connection init
 * 10 to indicate that the message is being sent by the client
 * 16 for last-packet flag (sent by the client, indicates that this is the last packet of the message, server replies with
 *  ACK and transmission is ended)
 */
typedef struct customPktHeader{
    int crcChecksum;
    short packetNumber;
    unsigned char type;
    char message[1451]; //maximum size of the message in the packets needs to be 1451 bytes, because of the Ethernet II packet limit (1500B of payload)
}customPktHeader;

/**
 * @brief although message array in myHeader is allocated to 1451 bytes, we only use 512 because of UDP unreliability -
 * it's considered a safe payload byte amount, therefore whole size of 1451 Bytes as a data part of a payload is not used,
 * although the program can be easily changed to handle this payload size
 */

size_t sendSize = sizeof(int)+sizeof(unsigned char)+sizeof(short); //size of the customPktHeader structure (in bytes)
/**
 * Function that changes terminal mode to icanonical
 * If the terminal is in canonical mode, input cannot be inserted correctly (terminal reads only 4095 characters by default in canonical mode)
 * @return zero if no problems occur
 */
int clear_icanon(void) {
    struct termios settings;
    int result;
    result = tcgetattr (STDIN_FILENO, &settings);
    if (result < 0) {
        perror ("error in tcgetattr");
        return 1;
    }
    settings.c_lflag &= ~ICANON;
    result = tcsetattr (STDIN_FILENO, TCSANOW, &settings);
    if (result < 0) {
        perror ("error in tcsetattr");
        return 1;
    }
    return 0;
}

/**
 * Basic CRC32 algorithm
 * @param message Message to be hashed
 * @return CRC32-hashed message
 */
unsigned int crc32b(const unsigned char *message) {
    int i, j;
    unsigned int byte, crc, mask;
    i = 0;
    crc = 0xFFFFFFFF;

    while (message[i] != 0) {
        byte = message[i];            // Get next byte.
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
/**
 * Receiving part of the program - server receives the packet and replies either with ACK, resend-flag or integrity-error-flag
 * @return 0 if no errors are omitted
 */
int server() {
    int sockfd;     //socket file descriptor
    int num;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    //setting up socked to a file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("Socket create error");
        exit(1);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
        perror("Setsockopt error");
        exit(1);
    }
    //server credentials initialization
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) {
        perror("Bind error");
        exit(1);
    }
    printf("Server listening on IP %s and port %d\n",inet_ntoa(servaddr.sin_addr),PORT);

    ssize_t n,totalBytesReceived = 0;
    int expectedPacketIndex = 1;
    customPktHeader incomingPacket;    //custom header structure of incoming packet
    customPktHeader serverReply;   //header of the packet sent by the server as a reply
    clear_icanon();
    memset(incomingPacket.message, 0, sizeof(incomingPacket.message));  //clear incoming message field

    while ((n = recvfrom(sockfd, &incomingPacket, sizeof(incomingPacket), 0, (struct sockaddr *) &cliaddr, &addrlen)) > 0)  {
        if (incomingPacket.packetNumber > 0) {
            totalBytesReceived += n;
            if (incomingPacket.type == 4) { //if server receives initialization packet, replies with type 0 (ACK)
                serverReply.type = 0;
                sendto(sockfd, (char *) &serverReply, 64, MSG_WAITALL,
                       (struct sockaddr *) &cliaddr, addrlen);
            }
            if (incomingPacket.type == 10) { //if server receives message packet, it verifies its contents and replies accordingly
                expectedPacketIndex++;
                printf("Client: ");
                if (incomingPacket.crcChecksum == crc32b(incomingPacket.message)) {
                    serverReply.type = 0;
                    sendto(sockfd, (char *) &serverReply, 64, MSG_WAITALL, (struct sockaddr *) &cliaddr, addrlen); //sends ACK
                    printf("%s", incomingPacket.message);
                    fflush(stdout);
                    memset(incomingPacket.message, 0, sizeof(incomingPacket.message));
                } else {
                    serverReply.type = 1; //resend request
                    sendto(sockfd,(char*)&serverReply,64,0,(struct sockaddr*)&cliaddr,addrlen);
                }
            }

            if (incomingPacket.type == 16) {    //server replies with ACK to the last packet of the current transmission (type '16')
                serverReply.type = 0;
                sendto(sockfd, (char *) &serverReply, 64, MSG_WAITALL, (struct sockaddr *) &cliaddr, addrlen);
            }
        }
    } /*endwhile*/
    printf("Server stopped listening. Returning to main menu\n");
    close(sockfd);
    return 0;
}

#pragma clang diagnostic pop
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
/**
 * Transmitting part of the program
 * User inputs the message, then the message is sent to the server encapsuled in the custom packet
 * @return 0 if finished correctly
 */
int client() {
    clear_icanon();
    int sockfd;
    int mode = -1,resendAttempts = 0;
    customPktHeader header, response;
    char message[MAXMSGLEN];
    struct sockaddr_in servaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    short packetCounter = 1;    //counts how many packets were sent to the server

    //socket creation
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Client socket create error");
        exit(EXIT_FAILURE);
    }
    //server credentials setup
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    //testing the connection between server and client
    header.type = 4;
    header.packetNumber = 1;
    sendto(sockfd, (char *) &header, 64, 0, (struct sockaddr *) &servaddr, addrlen);

    //program has received response from the server, thus the connection is established
    if (recvfrom(sockfd, &response, sendSize, 0, (struct sockaddr *) &servaddr, &addrlen))
        printf("Succesfully connected to server. \n\n");

    while (mode != 5) {
        printf("\nInput 1 to send a text message\nInput 5 to end communication and return to main menu.\n");
        printf("Insert your choice: ");
        scanf("%d", &mode);
        if (mode == 5) {
            sendto(sockfd,0,0,0,(struct sockaddr*)&servaddr,addrlen);  //sends NULL packet to server, terminates the connection
        }

        int byteCounter = 0, i = 0;
        char c;
        response.type = 0;

        //text message sending
        if (mode == 1) {
            memset(message,0,sizeof(message));
            packetCounter = 1;
            getchar();
            printf("\nType your message: ");
            fgets(message, MAXMSGLEN, stdin);   //reads 'MAXLEN' characters from standard input
            fflush(stdin);
            memset(header.message,0,sizeof(header.message));

            while ((c = message[i]) != '\0') {    //reading message character by character and inserting the character to a new packet
                header.message[byteCounter] = c;
                i++;
                if ((byteCounter % (FRAG_SIZE - 1) == 0 && byteCounter != 0)) {    //if byteCounter has reached 512B, send the packet
                    header.type = 10; //packet type 10 - message sending indicator
                    header.packetNumber = packetCounter;
                    header.crcChecksum = crc32b(header.message);
                    sendto(sockfd, (char *) &header, sendSize + strlen(header.message), 0,
                           (struct sockaddr *) &servaddr, addrlen); //packet is completed - send it to server

                    recvfrom(sockfd,(char*)&response,sizeof(response),0,(struct sockaddr*)&servaddr,&addrlen);  //get server response
                    if (response.type == 1) {
                        sendto(sockfd, (char *) &header, sendSize + strlen(header.message), 0,
                               (struct sockaddr *) &servaddr, addrlen); //if resend-flag is received from server, send the packet again
                    }
                    packetCounter++;    //new packet has been succesfully sent - increment packetCounter
                    byteCounter = 0;    //reset the byteCounter - buffer is now empty
                    memset(header.message, 0, sizeof(header.message));
                } else ++byteCounter;   //if no packet is sent, just increment the byteCounter
            }

            //if there are any unsent data after the main cycle (buffer is not empty and byteCounter has not reached FRAG_SIZE value)
            if (byteCounter != 0) {
                header.type = 10;
                header.packetNumber = packetCounter++;
                header.crcChecksum = crc32b(header.message);
                sendto(sockfd, (char *) &header, sendSize + strlen(header.message), 0, (struct sockaddr *) &servaddr, addrlen);
                header.type = 16; //end of stream - send message-end flag to server
                header.packetNumber = (short)FRAG_SIZE;
                sendto(sockfd,(char*)&header,sendSize,0,(struct sockaddr*)&servaddr,addrlen);
                recvfrom(sockfd,(char*)&response,sizeof(response),0,(struct sockaddr*)&servaddr,&addrlen);
                if (response.type == 0) printf("Server has acknowledged the end of message stream.");
            }
            else {    //if there are not any unsent data in a buffer, send the message-end flag to server
                header.type = 16;
                header.packetNumber = (short)FRAG_SIZE;
                sendto(sockfd,(char*)&header,sendSize,0,(struct sockaddr*)&servaddr,addrlen);
                if (response.type == 0) printf("Server has acknowledged the end of message stream.");
            }
            printf("Message has been successfully sent.\n");
        }


        //Debug function: Packet with an intended error is sent - test whether the server handles the packets correctly
        if (mode == 4) {
            strcpy(header.message, "This is a test message.");
            header.type = 8;
            header.packetNumber = 0;        //this is a dummy index and should not be normally used
            header.crcChecksum = crc32b(header.message) + 1;      //malfunctioning message CRC on purpose
            sendto(sockfd, (char *)&header, sendSize+strlen(header.message), 0, (struct sockaddr *) &servaddr, addrlen);
            recvfrom(sockfd,(char*)&response,sizeof(response),0,(struct sockaddr*)&servaddr,&addrlen);
            resendAttempts = 1;
            while (resendAttempts < 5 && response.type != 0) {
                sendto(sockfd, (char *)&header, sendSize+strlen(header.message), 0, (struct sockaddr *) &servaddr, addrlen);
                recvfrom(sockfd,(char*)&response,sizeof(response),0,(struct sockaddr*)&servaddr,&addrlen);
                resendAttempts++;
            }
            if (response.type == 3) {
                printf("Server detected an error. Message not sent.\n");
            }
        }
    }
    printf("CLIENT: Returning to main menu.\n\n");
    close(sockfd);
    return 0;
}
/**
 * Main function includes a simple main menu with options to enter client and server modes.
 */
int main() {
    int option = 0;
    printf("\n*****************************************************\n");
    printf("*                 Network communicator              *\n");
    printf("*         PCN Assignment 2 (C) Lukas Misaga         *\n");
    printf("*****************************************************\n");
    printf("Main menu:\n1 : Client side\n2 : Server side\n\nInsert an option: ");
    while (option != 3) {
        scanf("%d", &option);
        switch (option) {
            case 1:
                client();
                break;
            case 2:
                server();
                break;
            case 3:
                exit(0);
            default :
                printf("Insert a correct option!!!\n");
                break;
        }
    }
    return 0;
}