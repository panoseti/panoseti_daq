// net_thread.c
//
// The network thread reads packets from the quabos
// and writes their content to the input buffer.

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "hashpipe.h"

#include "databuf.h"
#include "pff.h"
#include "dp.h"

// PKTSOCK Params
// (These should be only changed with caution as it need to change with MMAP)
#define PKTSOCK_BYTES_PER_FRAME (1024)
#define PKTSOCK_FRAMES_PER_BLOCK (4096)
#define PKTSOCK_NBLOCKS (512)
#define PKTSOCK_NFRAMES (PKTSOCK_FRAMES_PER_BLOCK * PKTSOCK_NBLOCKS)

// get the time difference
static uint64_t timeval_diff(struct timeval *start, struct timeval *end)
{
    struct timeval diff;
    diff.tv_sec = end->tv_sec - start->tv_sec;
    diff.tv_usec = end->tv_usec - start->tv_usec;

    if (diff.tv_usec < 0)
    {
        diff.tv_sec -= 1;
        diff.tv_usec += 1000000;
    }
    return diff.tv_sec * 1000000 + diff.tv_usec;
}

static int write_ph_snapshot_header(FILE *f, PACKET_HEADER *dataHeader)
{
    if (dataHeader->pkt_nsec > 999999999)
        dataHeader->pkt_nsec = 999999999;
    fprintf(f,
            "{ \"quabo_num\": %1u, \"pkt_num\": %10u, \"pkt_tai\": %4u, \"pkt_nsec\": %9u, \"tv_sec\": %10li, \"tv_usec\": %6li}",
            dataHeader->quabo_num,
            dataHeader->pkt_num,
            dataHeader->pkt_tai,
            dataHeader->pkt_nsec,
            dataHeader->tv_sec,
            dataHeader->tv_usec);
    return 0;
}

// write data into ph snapshot file
static void WritePHSnapshots(FILE *fp, PACKET_HEADER *header, uint8_t *data)
{
    // move the pointer to the beginning,
    // as we only need one pkt in the snapshot file.
    fseek(fp, 0, SEEK_SET);
    pff_start_json(fp);
    write_ph_snapshot_header(fp, header);
    pff_end_json(fp);
    pff_write_image(fp, PIXELS_PER_IMAGE * 2, data);
}

int write_img_snapshot_header(FILE *f, PACKET_HEADER *dataHeader)
{
    fprintf(f, "{\n");
    for (int i = 0; i < QUABO_PER_MODULE; i++)
    {
        if (dataHeader[i].pkt_nsec > 999999999)
            dataHeader[i].pkt_nsec = 999999999;
        fprintf(f,
                "   \"quabo_%1u\": { \"pkt_num\": %10u, \"pkt_tai\": %4u, \"pkt_nsec\": %9u, \"tv_sec\": %10li, \"tv_usec\": %6li}",
                i,
                dataHeader[i].pkt_num,
                dataHeader[i].pkt_tai,
                dataHeader[i].pkt_nsec,
                dataHeader[i].tv_sec,
                dataHeader[i].tv_usec);
        if (i < QUABO_PER_MODULE - 1)
        {
            fprintf(f, ", ");
        }
        fprintf(f, "\n");
    }
    fprintf(f, "}");
    return 0;
}

// write data into img snapshot file
static void WriteImgSnapshots(FILE *fp, PACKET_HEADER *header, uint8_t *data)
{
    // move the pointer to the beginning,
    // as we only need one pkt in the snapshot file.
    fseek(fp, 0, SEEK_SET);
    pff_start_json(fp);
    write_img_snapshot_header(fp, header);
    pff_end_json(fp);
    pff_write_image(fp, PIXELS_PER_IMAGE * 2 * 4, data);
    fflush(fp);
    fsync(fileno(fp));
}

// Initialization function for Hashpipe.
// This function is called once when the thread is created
// args: Arugments passed in by hashpipe framework.

static int init(hashpipe_thread_args_t *args)
{
    printf("\n\n-----------Start Setup of Input Thread--------------\n");
    // define default network params
    char bindhost[80];
    int bindport = 60001;
    // define the snapshot directory
    char ssdir[64];
    // snapshot interval time (ms), defaut is 100ms.
    int ssint = 100;
    hashpipe_status_t st = args->st;
    // set default values.
    strcpy(bindhost, "0.0.0.0");
    strcpy(ssdir, "/ramdisk");
    // Lock shared buffer to properly get and set values.
    hashpipe_status_lock_safe(&st);

    // Get info from status buffer if present
    // - get bind host and port from status buffer
    // - if we can't get these info from status buffer,
    // - we will use the default info set above.
    hgets(st.buf, "BINDHOST", 80, bindhost);
    hgeti4(st.buf, "BINDPORT", &bindport);
    // Get snapshot info
    hgets(st.buf, "SSDIR", 64, ssdir);
    hgeti4(st.buf, "SSINT", &ssint);
    // Store bind host/port info and other info in status buffer
    hputs(st.buf, "BINDHOST", bindhost);
    hputi4(st.buf, "BINDPORT", bindport);
    hputs(st.buf, "SSDIR", ssdir);
    hputi4(st.buf, "SSINT", ssint);
    hputi8(st.buf, "NPACKETS", 0);

    // Unlock shared buffer once complete.
    hashpipe_status_unlock_safe(&st);

    // Set up pktsocket
    struct hashpipe_pktsock *p_ps = (struct hashpipe_pktsock *)
        malloc(sizeof(struct hashpipe_pktsock));

    if (!p_ps)
    {
        perror(__FUNCTION__);
        return -1;
    }

    // Make frame_size be a divisor of block size so that frames will be
    // contiguous in mapped mempory.  block_size must also be a multiple of
    // page_size.  Easiest way is to oversize the frames to be 16384 bytes, which
    // is bigger than we need, but keeps things easy.
    //
    p_ps->frame_size = PKTSOCK_BYTES_PER_FRAME;

    // total number of frames
    p_ps->nframes = PKTSOCK_NFRAMES;

    // number of blocks
    p_ps->nblocks = PKTSOCK_NBLOCKS;

    // Opening Pktsocket to receive data.
    int rv = hashpipe_pktsock_open(p_ps, bindhost, PACKET_RX_RING);
    if (rv != HASHPIPE_OK)
    {
        hashpipe_error("net_thread", "Error opening pktsock.");
        pthread_exit(NULL);
    }

    // Store packet socket pointer in args
    args->user_data = p_ps;

    // Initialize the the starting values of the input buffer.
    HSD_input_databuf_t *db = (HSD_input_databuf_t *)args->obuf;
    for (int i = 0; i < db->header.n_block; i++)
    {
        db->block[i].header.INTSIG = 0;
    }
    printf("-----------Finished Setup of Input Thread------------\n\n");
    // Success!
    return 0;
}

// Check the acqmode of the packet coming in.
// p_frame: The pointer for the packet frame
// return 0 if acqmode is recognized and 1 otherwise

int check_acqmode(unsigned char *p_frame)
{
    if (!p_frame)
        return 0;
    unsigned char *pkt_data = PKT_UDP_DATA(p_frame);
    if (pkt_data[0] == 1 || pkt_data[0] == 2 || pkt_data[0] == 3 ||
        pkt_data[0] == 6 || pkt_data[0] == 7)
    {
        return 1;
    }
    hashpipe_pktsock_release_frame(p_frame);
    fprintf(stderr, "Bad acq mode in packet: %d\n", pkt_data[0]);
    return 0;
}

// parse a packet header.
// pkt_data: packet data
// block_header: The header struct of the current block to be written to.
// i: packet index for the block header.

static inline void get_header(
    unsigned char *pkt_data, int i, HSD_input_block_header_t *block_header)
{
    block_header->pkt_head[i].acq_mode = pkt_data[0];
    block_header->pkt_head[i].pkt_num = ((pkt_data[3] << 8) & 0xff00) | (pkt_data[2] & 0x00ff);
    block_header->pkt_head[i].mod_num = ((pkt_data[5] << 6) & 0x3fc0) | ((pkt_data[4] >> 2) & 0x003f);
    block_header->pkt_head[i].quabo_num = ((pkt_data[4]) & 0x03);

    // quabo only sends 10 bits of TAI
    block_header->pkt_head[i].pkt_tai = ((pkt_data[7] << 8) & 0x00000300) | ((pkt_data[6]) & 0x000000ff);

    block_header->pkt_head[i].pkt_nsec = ((pkt_data[13] << 24) & 0xff000000) | ((pkt_data[12] << 16) & 0x00ff0000) | ((pkt_data[11] << 8) & 0x0000ff00) | ((pkt_data[10]) & 0x000000ff);
}

// Signal interrupt function where it is changed when a SIGINT is received by the program.
// This value is meant to be passed to the other threads to stop the program gracefully.

static int INTSIG;
void INThandler(int signum)
{
    INTSIG = 1;
}

// main function for network thread.
// make sure to use a while loop.
// args: Arguments passed in by the hashpipe framework
//
static void *run(hashpipe_thread_args_t *args)
{
    signal(SIGINT, INThandler);
    INTSIG = 0;

    printf("\n---------------Running Input Thread-----------------\n\n");

    // Create pointers hashpipe args
    HSD_input_databuf_t *db = (HSD_input_databuf_t *)args->obuf;
    hashpipe_status_t st = args->st;
    const char *status_key = args->thread_desc->skey;

    int rv, n;
    uint64_t mcnt = 0; // Mcount of
    int block_idx = 0; // The input buffer block index
    HSD_input_block_header_t *blockHeader;
    unsigned char *pkt_data;                  // Packet Data from PKT_UDP_DATA
    struct timeval nowTime;                   // Current NTP UTC time
    struct timeval lastImg16Time, lastPHTime; // Timestamp for the last pkt
    uint64_t tdiff = 0;                       // time difference(us)
    lastPHTime.tv_sec = 0;
    lastPHTime.tv_usec = 0;
    uint8_t imgfull = 0; // this is for indicating if we get a full image from 4 quabos
    int rc;

    // Compute the pkt_loss in the compute thread

    unsigned int pktsock_pkts = 0;  // Stats counter for socket packet
    unsigned int pktsock_drops = 0; // Stats counter for dropped socket packet
    uint64_t npackets = 0;          // number of received packets
    int bindport = 0;
    char ssdir[64];
    int ssint = 0;
    uint8_t imgbuf[2048];
    uint8_t quabo_num = 0;
    PACKET_HEADER imgheader[4];

    hashpipe_status_lock_safe(&st);

    // Get info from status buffer if present (no change if not present)
    hgeti4(st.buf, "BINDPORT", &bindport);
    hputs(st.buf, status_key, "running");
    hgets(st.buf, "SSDIR", 64, ssdir);
    hgeti4(st.buf, "SSINT", &ssint);
    hashpipe_status_unlock_safe(&st);

    // Get pktsock from args
    struct hashpipe_pktsock *p_ps = (struct hashpipe_pktsock *)args->user_data;
    pthread_cleanup_push(free, p_ps);
    pthread_cleanup_push((void (*)(void *))hashpipe_pktsock_close, p_ps);

    // Drop all packets to date
    unsigned char *p_frame;
    while (p_frame = hashpipe_pktsock_recv_frame_nonblock(p_ps))
    {
        hashpipe_pktsock_release_frame(p_frame);
    }
    // let's create snapshot files here
    char ssmovie[64];
    char ssph[64];
    snprintf(ssmovie, sizeof(ssmovie), "%s/module_0/obs_snapshot/start_0.img16.seqno_0.pff", ssdir);
    snprintf(ssph, sizeof(ssph), "%s/module_0/obs_snapshot/start_0.ph256.seqno_0.pff", ssdir);
    hashpipe_info(__FUNCTION__, "Movie snapshot: %s", ssmovie);
    hashpipe_info(__FUNCTION__, "PH snapshot: %s", ssph);
    FILE *mov16_fp = fopen(ssmovie, "w");
    FILE *ph_fp = fopen(ssph, "w");
    //  Main Loop
    while (run_threads())
    {
        // Update the info of the buffer
        hashpipe_status_lock_safe(&st);
        hputs(st.buf, status_key, "waiting");
        hputi4(st.buf, "NETBKOUT", block_idx);
        hputi8(st.buf, "NETMCNT", mcnt);
        hputi8(st.buf, "NPACKETS", npackets);
        hashpipe_status_unlock_safe(&st);

        // Wait for data
        // Wait for new block to be free, then clear it
        // if necessary and fill its header with new values.

        while ((rv = HSD_input_databuf_wait_free(db, block_idx)) != HASHPIPE_OK)
        {
            if (rv == HASHPIPE_TIMEOUT)
            {
                // Setting the statues of the buffer as blocked.
                hashpipe_status_lock_safe(&st);
                hputs(st.buf, status_key, "blocked");
                hashpipe_status_unlock_safe(&st);
                continue;
            }
            else
            {
                hashpipe_error(__FUNCTION__, "error waiting for free databuf");
                pthread_exit(NULL);
                break;
            }
        }

        // Update the progress of the buffer to be receiving

        hashpipe_status_lock_safe(&st);
        hputs(st.buf, status_key, "receiving");
        hashpipe_status_unlock_safe(&st);

        blockHeader = &(db->block[block_idx].header);
        blockHeader->n_pkts_in_block = 0;

        // Loop through all of the packets in the buffer block.
        for (int i = 0; i < IN_PKT_PER_BLOCK; i++)
        {
            // Check if the INTSIG flag is set
            if (INTSIG)
                break;

            // Recv all of the UDP packets from PKTSOCK
            do
            {
                p_frame = hashpipe_pktsock_recv_udp_frame_nonblock(p_ps, bindport);
            } while (!p_frame && run_threads() && !INTSIG && !check_acqmode(p_frame));

            // Check to see if the threads are still running. If not then terminate
            if (!run_threads() || INTSIG)
                break;

            // TODO
            // Check Packet Number at the beginning and end to see if we lost any packets
            npackets++;
            pkt_data = (unsigned char *)PKT_UDP_DATA(p_frame);
            get_header(pkt_data, i, blockHeader);

            // Copy the packets in PKTSOCK to the input circular buffer
            // Size is based on whether or not the mode is 16 bit or 8 bit
            if (blockHeader->pkt_head[i].acq_mode < 4)
            {
                memcpy(db->block[block_idx].data_block + i * BYTES_PER_PKT_IMAGE,
                       pkt_data + BYTE_PKT_HEADER,
                       BYTES_PER_PKT_IMAGE * sizeof(unsigned char));
            }
            else
            {
                memcpy(db->block[block_idx].data_block + i * BYTES_PER_PKT_IMAGE,
                       pkt_data + BYTE_PKT_HEADER,
                       BYTES_PER_8BIT_PKT_IMAGE * sizeof(unsigned char));
            }

            // Time stamp the packets and pass it into the shared buffer
            rc = gettimeofday(&nowTime, NULL);
            if (rc == 0)
            {
                blockHeader->pkt_head[i].tv_sec = nowTime.tv_sec;
                blockHeader->pkt_head[i].tv_usec = nowTime.tv_usec;
            }
            else
            {
                fprintf(stderr, "gettimeofday() failed, errno = %d\n", errno);
                blockHeader->pkt_head[i].tv_sec = 0;
                blockHeader->pkt_head[i].tv_usec = 0;
            }

            blockHeader->n_pkts_in_block++;

            // check the timestamp here;
            // then decide is we need to write the data into snapshot files.
            if (blockHeader->pkt_head[i].acq_mode == 0x01)
            {
                // for PH snapshots
                tdiff = timeval_diff(&lastPHTime, &nowTime);
                if (tdiff > ssint * 1000)
                {
                    WritePHSnapshots(ph_fp, &blockHeader->pkt_head[i], pkt_data + BYTE_PKT_HEADER);
                    lastPHTime.tv_sec = nowTime.tv_sec;
                    lastPHTime.tv_usec = nowTime.tv_usec;
                }
            }
            else if (blockHeader->pkt_head[i].acq_mode == 0x02 || blockHeader->pkt_head[i].acq_mode == 0x03)
            {
                // if we get four packets from four different quabos,
                // imgfull will be 0xf.
                // then we will write the data into the snapshot file.
                quabo_num = blockHeader->pkt_head[i].quabo_num;
                imgfull |= 1 << quabo_num;
                // TODO: group the mov images?
                memcpy(imgbuf + quabo_num * 512, pkt_data + BYTE_PKT_HEADER, 512);
                memcpy(&imgheader[quabo_num], &blockHeader->pkt_head[i], sizeof(PACKET_HEADER));
                if (imgfull == 0xf)
                {
                    imgfull = 0;
                    // for Img16 snapshots
                    tdiff = timeval_diff(&lastImg16Time, &nowTime);
                    if (tdiff > ssint * 1000)
                    {
                        WriteImgSnapshots(mov16_fp, imgheader, imgbuf);
                        lastImg16Time.tv_sec = nowTime.tv_sec;
                        lastImg16Time.tv_usec = nowTime.tv_usec;
                    }
                }
            }

            // Release the hashpipe frame back to the kernel to gather data
            hashpipe_pktsock_release_frame(p_frame);

            pthread_testcancel();
        }
        // Send the signal of SIGINT to the blockHeader
        blockHeader->INTSIG = INTSIG;

        // Get stats from packet socket
        hashpipe_pktsock_stats(p_ps, &pktsock_pkts, &pktsock_drops);

        hashpipe_status_lock_safe(&st);
        hputi8(st.buf, "NPACKETS", npackets);
        hputu8(st.buf, "NETRECV", pktsock_pkts);
        hputu8(st.buf, "NETDROPS", pktsock_drops);
        hashpipe_status_unlock_safe(&st);

        // Mark block as full
        if (HSD_input_databuf_set_filled(db, block_idx) != HASHPIPE_OK)
        {
            hashpipe_error(__FUNCTION__, "error waiting for databuf filled call");
            pthread_exit(NULL);
        }

        db->block[block_idx].header.mcnt = mcnt;
        block_idx = (block_idx + 1) % db->header.n_block;
        mcnt++;

        // exit if thread has been cancelled
        pthread_testcancel();

        // Break out when SIGINT is found
        if (INTSIG)
        {
            printf("NET_THREAD Ended\n");
            break;
        }
    }

    // close the snapshot files
    fclose(mov16_fp);
    fclose(ph_fp);

    pthread_cleanup_pop(1); // Closes push(hashpipe_pktsock_close)
    pthread_cleanup_pop(1); // Closes push(free)

    printf("Returned Net_thread\n");
    return THREAD_OK;
}

// Sets the functions and buffers for this thread

static hashpipe_thread_desc_t HSD_net_thread = {
    name : "net_thread",
    skey : "NETSTAT",
    init : init,
    run : run,
    ibuf_desc : {NULL},
    obuf_desc : {HSD_input_databuf_create}
};

static __attribute__((constructor)) void ctor()
{
    register_hashpipe_thread(&HSD_net_thread);
}
