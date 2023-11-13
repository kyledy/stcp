/************************************************************************
 * Adapted from a course at Boston University for use in CPSC 317 at UBC
 *
 *
 * The interfaces for the STCP sender (you get to implement them), and a
 * simple application-level routine to drive the sender.
 *
 * This routine reads the data to be transferred over the connection
 * from a file specified and invokes the STCP send functionality to
 * deliver the packets as an ordered sequence of datagrams.
 *
 * Version 2.0
 *
 *
 *************************************************************************/


#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/file.h>

#include "stcp.h"

#define STCP_SUCCESS 1
#define STCP_ERROR -1
#define STCP_SYN_SENT 0x6
#define STCP_FIN_WAIT 0x7

typedef struct {
    int state;
    int fd;
    unsigned int seq;
    unsigned int ack;
    unsigned short rwnd;
    unsigned short swnd; 
    int num_segments; 
} stcp_send_ctrl_blk;

typedef struct {
    packet *pkt; 
    struct linked_list *next; 
} linked_list; 

/*
 * Send STCP. This routine is to send all the data (len bytes).  If more
 * than MSS bytes are to be sent, the routine breaks the data into multiple
 * packets. It will keep sending data until the send window is full or all
 * the data has been sent. At which point it reads data from the network to,
 * hopefully, get the ACKs that open the window. You will need to be careful
 * about timing your packets and dealing with the last piece of data.
 *
 * Your sender program will spend almost all of its time in either this
 * function or in tcp_close().  All input processing (you can use the
 * function readWithTimeout() defined in stcp.c to receive segments) is done
 * as a side effect of the work of this function (and stcp_close()).
 *
 * The function returns STCP_SUCCESS on success, or STCP_ERROR on error.
 */
int stcp_send(stcp_send_ctrl_blk *stcp_CB, unsigned char* data, int length) {
    
    // stcp_send_ctrl_blk *cb = stcp_CB;
    // int fd = stcp_CB->fd;
    // int swnd = stcp_CB->swnd;
    // int rwnd = stcp_CB->rwnd;

    // size_t len = sizeof(data); 
    // unsigned char buff[STCP_MSS];

    // linked_list *head = NULL;
    // linked_list *tail = NULL;

    // int timeout = STCP_INITIAL_TIMEOUT;

    // while (len > 0) {

    //     if (swnd < rwnd) {

    //         int current_segment_size = (len - offset < STCP_MTU) ? len - offset : STCP_MTU; 
    //         strncpy(buff, data, current_segment_size); 
    //         packet *pkt = (packet*) malloc(sizeof(packet)); 
    //         createSegment(&pkt, 0, cb->rwnd, cb->seq, cb->ack, buff, current_segment_size);

    //         if (!head) {
    //             head = (linked_list*) malloc(sizeof(linked_list)); 
    //             head->pkt = pkt; 
    //             head->next = NULL; 
    //             tail = head; 
    //             num_segments = 1; 
    //         } else {
    //             linked_list* temp = (linked_list*) malloc(sizeof(linked_list)); 
    //             tail->next = temp; 
    //             tail = tail->next; 
    //             num_segments++;
    //         }

    //         htonHdr(pkt->hdr); 
    //         pkt->hdr->checksum = ipchecksum(pkt, pkt->len);
    //         ntohHdr(pkt->hdr); 
    //     }
    // }

    return STCP_SUCCESS;
}



/*
 * Open the sender side of the STCP connection. Returns the pointer to
 * a newly allocated control block containing the basic information
 * about the connection. Returns NULL if an error happened.
 *
 * If you use udp_open() it will use connect() on the UDP socket
 * then all packets then sent and received on the given file
 * descriptor go to and are received from the specified host. Reads
 * and writes are still completed in a datagram unit size, but the
 * application does not have to do the multiplexing and
 * demultiplexing. This greatly simplifies things but restricts the
 * number of "connections" to the number of file descriptors and isn't
 * very good for a pure request response protocol like DNS where there
 * is no long term relationship between the client and server.
 */
stcp_send_ctrl_blk * stcp_open(char *destination, int sendersPort,
                             int receiversPort) {

    logLog("init", "Sending from port %d to <%s, %d>", sendersPort, destination, receiversPort);
    // Since I am the sender, the destination and receiversPort name the other side
    int fd = udp_open(destination, receiversPort, sendersPort);

    if (fd < 0) return NULL;

    stcp_send_ctrl_blk *cb = malloc(sizeof cb);
    packet pkt;

    cb->seq = (unsigned int) rand();
    cb->ack = (unsigned int) rand();

    createSegment(&pkt, SYN, STCP_MAXWIN, cb->seq, cb->ack, NULL, 0);

    htonHdr(pkt.hdr);
    pkt.hdr->checksum = ipchecksum(pkt.hdr, pkt.len);
    send(fd, pkt.hdr, pkt.len, 0);
    ntohHdr(pkt.hdr);

    cb->state = STCP_SYN_SENT;

    int timeout = STCP_INITIAL_TIMEOUT;

    while (1) {

        unsigned char buff[STCP_MTU];

        int len = readWithTimeout(fd, buff, timeout);

        if (len == STCP_READ_TIMED_OUT) {
            timeout = stcpNextTimeout(timeout);
            htonHdr(pkt.hdr);
            send(fd, pkt.hdr, pkt.len, 0);
            ntohHdr(pkt.hdr);
            continue;
        }

        if (len == STCP_READ_PERMANENT_FAILURE) return NULL;

        tcpheader *hdr = (tcpheader *) buff;
        
        if (ipchecksum(hdr, len) == 0 && getSyn(hdr)) {
            ntohHdr(hdr);
            cb->state = STCP_ESTABLISHED;
            cb->fd = fd;
            cb->seq++;
            cb->ack = hdr->seqNo + 1;
            cb->rwnd = hdr->windowSize;
            cb->swnd = 0;
        } else continue;

        return cb;
    }
}


/*
 * Make sure all the outstanding data has been transmitted and
 * acknowledged, and then initiate closing the connection. This
 * function is also responsible for freeing and closing all necessary
 * structures that were not previously freed, including the control
 * block itself.
 *
 * Returns STCP_SUCCESS on success or STCP_ERROR on error.
 */
int stcp_close(stcp_send_ctrl_blk *cb) {
    
    int fd = cb->fd;
    packet pkt; 
    createSegment(&pkt, FIN, cb->rwnd, cb->seq, cb->ack, NULL, 0);

    htonHdr(pkt.hdr); 
    pkt.hdr->checksum = ipchecksum(pkt.hdr, pkt.len);
    send(fd, pkt.hdr, pkt.len, 0);
    ntohHdr(pkt.hdr);

    cb->state = STCP_FIN_WAIT;

    int timeout = STCP_INITIAL_TIMEOUT;

    while (1) {

        unsigned char buff[STCP_MTU];

        int len = readWithTimeout(fd, buff, timeout); 

        if (len == STCP_READ_TIMED_OUT) {
            timeout = stcpNextTimeout(timeout);
            htonHdr(pkt.hdr);
            send(fd, pkt.hdr, pkt.len, 0);
            ntohHdr(pkt.hdr);
            continue; 
        }

        if (len == STCP_READ_PERMANENT_FAILURE) return STCP_ERROR;

        tcpheader *hdr = (tcpheader*) buff; 

        if (ipchecksum(hdr, len == 0) && getFin(hdr)) {
            
            packet finAck; 
            createSegment(&finAck, ACK, cb->rwnd, cb->seq, cb->ack, NULL, 0);
            
            htonHdr(pkt.hdr);
            send(fd, pkt.hdr, pkt.len, 0);

            cb->state = STCP_CLOSED;
            close(cb->fd);  
            free(cb); 
            return STCP_SUCCESS;
        } else continue; 
    }
}
/*
 * Return a port number based on the uid of the caller.  This will
 * with reasonably high probability return a port number different from
 * that chosen for other uses on the undergraduate Linux systems.
 *
 * This port is used if ports are not specified on the command line.
 */
int getDefaultPort() {
    uid_t uid = getuid();
    int port = (uid % (32768 - 512) * 2) + 1024;
    assert(port >= 1024 && port <= 65535 - 1);
    return port;
}

/*
 * This application is to invoke the send-side functionality.
 */
int main(int argc, char **argv) {
    stcp_send_ctrl_blk *cb;

    char *destinationHost;
    int receiversPort, sendersPort;
    char *filename = NULL;
    int file;
    /* You might want to change the size of this buffer to test how your
     * code deals with different packet sizes.
     */
    unsigned char buffer[STCP_MSS];
    int num_read_bytes;

    logConfig("sender", "init,segment,error,failure,packet");
    /* Verify that the arguments are right */
    if (argc > 5 || argc == 1) {
        fprintf(stderr, "usage: sender DestinationIPAddress/Name receiveDataOnPort sendDataToPort filename\n");
        fprintf(stderr, "or   : sender filename\n");
        exit(1);
    }
    if (argc == 2) {
        filename = argv[1];
        argc--;
    }

    // Extract the arguments
    destinationHost = argc > 1 ? argv[1] : "localhost";
    receiversPort = argc > 2 ? atoi(argv[2]) : getDefaultPort();
    sendersPort = argc > 3 ? atoi(argv[3]) : getDefaultPort() + 1;
    if (argc > 4) filename = argv[4];

    /* Open file for transfer */
    file = open(filename, O_RDONLY);
    if (file < 0) {
        logPerror(filename);
        exit(1);
    }

    /*
     * Open connection to destination.  If stcp_open succeeds the
     * control block should be correctly initialized.
     */
    cb = stcp_open(destinationHost, sendersPort, receiversPort);
    if (cb == NULL) {
        exit(1);
    }

    /* Start to send data in file via STCP to remote receiver. Chop up
     * the file into pieces as large as max packet size and transmit
     * those pieces.
     */
    while (1) {
        num_read_bytes = read(file, buffer, sizeof(buffer));

        /* Break when EOF is reached */
        if (num_read_bytes <= 0)
            break;

        if (stcp_send(cb, buffer, num_read_bytes) == STCP_ERROR) {
            // possibly free linked list / malloc'd memory here 
            close(cb->fd); 
            free(cb);
            exit(1);
        }
    }

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        close(cb->fd); 
        free(cb); 
        exit(1); 
    }

    return 0;
}
