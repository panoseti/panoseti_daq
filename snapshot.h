#ifndef _SNAPSHOT_H_
#define _SNAPSHOT_H_

#include <stdint.h>
#include <sys/time.h>
#include "image.h"
#include <stdio.h>
#include "databuf.h"
#include "pff.h"

#ifdef __cplusplus
extern "C"
{
#endif

// Timeout for UDS connections
#define UDS_CONNECTION_TIMEOUT_US 15000000UL // 15 seconds
// UDS socket idle check period
#define UDS_IDLE_CHECK_PERIOD_US 5000000UL // 5 seconds

#define UDS_PATH_TEMPLATE "/tmp/hashpipe_grpc.dp_%s.sock"

    // get the time difference
    uint64_t timeval_diff(struct timeval *start, struct timeval *end);

    // Structure representing a Unix Domain Socket connection.
    typedef struct uds_connection
    {
        char dp_name[16];
        int fd; // The connected socket
        char socket_path[128];
        struct timeval last_successful_write_time;
        struct uds_connection *next;
    } uds_connection_t;

    // Check and close idle UDS connections
    void check_uds_connections(struct timeval *now);

    /**
     * @brief Gets the head of the list of Unix Domain Socket connections.
     *
     * @return Pointer to the head of the list of UDS connections.
     */
    uds_connection_t *get_uds_connections_list_head();

    /**
     * @brief Writes a four-packet image snapshot to a filesystem file.
     *
     * @param fp Pointer to the file to write to.
     * @param header Pointer to an array of 4 PACKET_HEADER structs.
     * @param data Pointer to the assembled image data (2048 bytes).
     */
    void WriteImgSnapshots(FILE *fp, PACKET_HEADER *header, uint8_t *data);

    /**
     * @brief Writes a single-packet pulse-height snapshot to a filesystem file.
     *
     * @param fp Pointer to the file to write to.
     * @param header Pointer to the packet's header.
     * @param data Pointer to the pulse-height image data (512 bytes).
     */
    void WritePHSnapshots(FILE *fp, PACKET_HEADER *header, uint8_t *data);

    /**
     * @brief Sends a four-packet image snapshot over a Unix Domain Socket.
     *
     * @param dp The specific data product type (e.g., DP_BIT16_IMG, DP_BIT8_IMG).
     * @param header Pointer to an array of 4 PACKET_HEADER structs.
     * @param data Pointer to the assembled image data.
     */
    void write_32x32_to_uds(DATA_PRODUCT dp, PACKET_HEADER *header, uint8_t *data);

    /**
     * @brief Sends a single-packet pulse-height snapshot over a Unix Domain Socket.
     *
     * @param dp The specific data product type (e.g., DP_PH_256_IMG).
     * @param header Pointer to the packet's header.
     * @param data Pointer to the pulse-height image data (512 bytes).
     */
    void write_16x16_to_uds(DATA_PRODUCT dp, PACKET_HEADER *header, uint8_t *data);

    // Structure representing one snapshot
    typedef struct snapshot
    {
        DATA_PRODUCT dp;
        PACKET_HEADER headers[4];
        uint8_t data[BYTES_PER_PKT_IMAGE * 4]; // 2048 bytes for a 32x32 16-bit per pixel image
        uint8_t quabo_bitmap;                  // Bitmap to track which quabos are present in the snapshot
        struct timeval last_update_time;       // Last time this snapshot was updated
        struct snapshot *next;
    } snapshot_t;

    struct module_snapshot_buffer
    {
        uint16_t module_id;
        snapshot_t *snapshot_head;
        snapshot_t *snapshot_tail;
        module_snapshot_buffer *next;

        module_snapshot_buffer(uint16_t module_id)
        {
            this->module_id = module_id;
            this->snapshot_head = NULL;
            this->snapshot_tail = NULL;
            this->next = NULL;

            // Initialize linked list of snapshots for each data product
            for (DATA_PRODUCT dp = DP_BIT16_IMG; dp < DP_NONE; dp = (DATA_PRODUCT)(dp + 1))
            {
                snapshot_t *s = (snapshot_t *)malloc(sizeof(snapshot_t));
                if (!s)
                {
                    fprintf(stderr, "Failed to allocate memory for snapshot\n");
                    exit(EXIT_FAILURE);
                }
                memset(s, 0, sizeof(snapshot_t));
                s->dp = dp;
                s->next = NULL;
                if (this->snapshot_head == NULL)
                {
                    this->snapshot_head = s;
                    this->snapshot_tail = s;
                }
                else
                {
                    this->snapshot_tail->next = s;
                    this->snapshot_tail = s;
                }
            }
        }

        snapshot_t *get_snapshot(DATA_PRODUCT dp)
        {
            for (snapshot_t *current = snapshot_head; current != NULL; current = current->next)
            {
                if (current->dp == dp)
                {
                    return current;
                }
            }
            return NULL; // Not found
        }

        void update_snapshot(PACKET_HEADER *header, uint8_t *data, struct timeval *nowTime, int snapshot_interval_ms, int group_ph_frames)
        {
            char acq_mode = header->acq_mode;
            int quabo_num = header->quabo_num;
            DATA_PRODUCT dp = acq_mode_to_dp(acq_mode, group_ph_frames);
            snapshot_t *s = this->get_snapshot(dp);
            if (!s)
                return; // Snapshot for this data product not found

            bool write_snapshot = false;
            uint64_t tdiff = timeval_diff(&s->last_update_time, nowTime);
            if (tdiff > snapshot_interval_ms * 1000)
            {
                write_snapshot = true;
            }

            bool is_single_quabo = (dp == DP_PH_256_IMG);
            bool is_complete = false;

            if (is_single_quabo)
            {
                quabo16_to_quabo16_copy(data, quabo_num, s->data);
                memcpy(&s->headers[0], header, sizeof(PACKET_HEADER));
                is_complete = true;
            }
            else
            {
                s->quabo_bitmap |= 1 << quabo_num;
                memcpy(&s->headers[quabo_num], header, sizeof(PACKET_HEADER));

                if (bytes_per_pixel(dp) == 1)
                {
                    quabo8_to_module8_copy(data, quabo_num, s->data);
                }
                else if (bytes_per_pixel(dp) == 2)
                {
                    quabo16_to_module16_copy(data, quabo_num, s->data);
                }

                if (s->quabo_bitmap == 0xf)
                {
                    is_complete = true;
                }
            }

            if (is_complete && write_snapshot)
            {
                if (is_single_quabo)
                {
                    write_16x16_to_uds(dp, &s->headers[0], s->data);
                }
                else
                {
                    write_32x32_to_uds(dp, s->headers, s->data);
                }

                // Reset for next snapshot
                s->last_update_time.tv_sec = nowTime->tv_sec;
                s->last_update_time.tv_usec = nowTime->tv_usec;
                memset(s->headers, 0, sizeof(s->headers));
                memset(s->data, 0, sizeof(s->data));
                s->quabo_bitmap = 0;
            }
        }

        ~module_snapshot_buffer()
        {
            for (snapshot_t *current = snapshot_head; current;)
            {
                snapshot_t *next = current->next;
                free(current);
                current = next;
            }
        }
    };

    void init_module_snapshot_buffers(char *module_config, module_snapshot_buffer **snapshot_buffers);

    module_snapshot_buffer *get_snapshot_buffer(uint16_t module_id, module_snapshot_buffer *snapshot_buffers);

    /**
     * @brief Frees all UDS connection objects in g_uds_connections, closing
     *        any open file descriptors, and resets the list to NULL.
     *        Call from net_thread at teardown.
     */
    void free_uds_connections(void);

    /**
     * @brief Deletes all module_snapshot_buffer objects in the linked list
     *        (each destructor frees the internal snapshot_t chain).
     *        Call from net_thread at teardown.
     */
    void free_module_snapshot_buffers(module_snapshot_buffer *buffers);

#ifdef __cplusplus
}
#endif

#endif // _SNAPSHOT_H_
