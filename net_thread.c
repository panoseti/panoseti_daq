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
#include "snapshot.h"
#include "pff.h"
#include "dp.h"
#include "image.h"
#include "net_thread.h"


static int group_ph_frames;
static module_snapshot_buffer_t *snapshot_buffers;

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

    char module_config[STR_BUFFER_SIZE];
    sprintf(module_config, CONFIGFILE_DEFAULT);
    group_ph_frames = 0; // Default to not grouping frame

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
    // Get ph frame grouping info
    hgeti4(st.buf, "GROUPPHFRAMES", &group_ph_frames);
    // Get snapshot info
    hgets(st.buf, "SSDIR", 64, ssdir);
    hgeti4(st.buf, "SSINT", &ssint);
    // Store bind host/port info and other info in status buffer
    hputs(st.buf, "BINDHOST", bindhost);
    hputi4(st.buf, "BINDPORT", bindport);
    hputs(st.buf, "SSDIR", ssdir);
    hputi4(st.buf, "SSINT", ssint);
    hputi8(st.buf, "NPACKETS", 0);
    // Get module config path
    hgets(st.buf, "CONFIG", STR_BUFFER_SIZE, module_config);
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

    // Initialize snapshot buffers
    snapshot_buffers = NULL;
    init_module_snapshot_buffers(module_config, snapshot_buffers);
    if (snapshot_buffers == NULL) {
        hashpipe_error("net_thread", "Failed to initialize snapshot buffers\n");
        pthread_exit(NULL);
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

// Handle SIGPIPE signal: expected when the grpc server is re-initialized mid-observation
void SIGPIPEhandler(int signum)
{
    char buffer[sizeof "2011-10-08T07:07:09Z"];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%S%z", tm_info);
    hashpipe_info(__FUNCTION__, "SIGPIPE received at %s\n", buffer);
}

// main function for network thread.
// make sure to use a while loop.
// args: Arguments passed in by the hashpipe framework
//
static void *run(hashpipe_thread_args_t *args)
{
    signal(SIGINT, INThandler);
    signal(SIGPIPE, SIGPIPEhandler);
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
    uint8_t oimgbuf[512];
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
    // char ssmovie[128];
    // char ssph[128];
    // snprintf(ssmovie, sizeof(ssmovie), "%s/module_0/obs_snapshot/start_0.img16.seqno_0.pff", ssdir);
    // snprintf(ssph, sizeof(ssph), "%s/module_0/obs_snapshot/start_0.ph256.seqno_0.pff", ssdir);
    // hashpipe_info(__FUNCTION__, "Movie snapshot: %s", ssmovie);
    // hashpipe_info(__FUNCTION__, "PH snapshot: %s", ssph);
    // FILE *mov16_fp = fopen(ssmovie, "w");
    // FILE *ph_fp = fopen(ssph, "w");

    // track last successful grpc snapshot send time
    struct timeval last_idle_check_time;
    gettimeofday(&last_idle_check_time, NULL);

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

            // ===========
            // Snapshot code
            // ===========

            // check idle sockets to detect grpc re-init
            if (timeval_diff(&last_idle_check_time, &nowTime) > UDS_IDLE_CHECK_PERIOD_US) {
                check_uds_connections(&nowTime);
                last_idle_check_time = nowTime; // Update the check time
            }

            // Fetch the snapshot buffer for the current module
            module_snapshot_buffer_t *snapshot_buffer = get_snapshot_buffer(blockHeader->pkt_head[i].mod_num, snapshot_buffers);
            if (snapshot_buffer) {
                snapshot_buffer->update_snapshot(
                    &blockHeader->pkt_head[i],
                    pkt_data + BYTE_PKT_HEADER,
                    &nowTime,
                    ssint
                );
                // PACKET_HEADER pkt_head = blockHeader->pkt_head[i];

                // // char acq_mode = pkt_head.acq_mode; 
                // // DATA_PRODUCT dp = acq_mode_to_dp(acq_mode, group_ph_frames);
                // if (dp == DP_PH_256_IMG || dp == DP_PH_1024_IMG)
                // {
                //     snapshot_buffer->update_snapshot(&blockHeader->pkt_head[i], pkt_data + BYTE_PKT_HEADER);
                //     // for PH snapshots
                //     tdiff = timeval_diff(&lastPHTime, &nowTime);
                //     if (tdiff > ssint * 1000)
                //     {
                //         // WritePHSnapshots(ph_fp, &blockHeader->pkt_head[i], pkt_data + BYTE_PKT_HEADER);
                //         WritePHSnapshotsToUds(DP_PH_256_IMG, &blockHeader->pkt_head[i], pkt_data + BYTE_PKT_HEADER);
                //         lastPHTime.tv_sec = nowTime.tv_sec;
                //         lastPHTime.tv_usec = nowTime.tv_usec;
                //     }
                // }
                // else if (dp == DP_BIT16_IMG)
                // {
                //     // if we get four packets from four different quabos,
                //     // imgfull will be 0xf.
                //     // then we will write the data into the snapshot file.
                //     quabo_num = blockHeader->pkt_head[i].quabo_num;
                //     imgfull |= 1 << quabo_num;
                //     // TODO: group the mov images?
                //     quabo16_to_module16_copy(pkt_data + BYTE_PKT_HEADER, quabo_num, oimgbuf);
                //     memcpy(imgbuf + quabo_num * 512, oimgbuf, 512);
                //     memcpy(&imgheader[quabo_num], &blockHeader->pkt_head[i], sizeof(PACKET_HEADER));
                //     if (imgfull == 0xf)
                //     {
                //         imgfull = 0;
                //         // for Img16 snapshots
                //         tdiff = timeval_diff(&lastImg16Time, &nowTime);
                //         if (tdiff > ssint * 1000)
                //         {
                //             // DATA_PRODUCT img_dp = (imgheader[0].acq_mode == 0x03) ? DP_BIT8_IMG : DP_BIT16_IMG;
                //             // WriteImgSnapshots(mov16_fp, imgheader, imgbuf);
                //             WriteImgSnapshotsToUds(dp, imgheader, imgbuf);
                //             lastImg16Time.tv_sec = nowTime.tv_sec;
                //             lastImg16Time.tv_usec = nowTime.tv_usec;
                //         }
                //     }
                // }
            }

            // ==== End snapshot code ====

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
    // fclose(mov16_fp);
    // fclose(ph_fp);

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
