#ifndef _SNAPSHOT_H_
#define _SNAPSHOT_H_

#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>
#include "databuf.h" 
#include "pff.h"

#ifdef __cplusplus
extern "C" {
#endif

// Timeout for UDS connections
#define UDS_CONNECTION_TIMEOUT_US 5000000  // 5 seconds
// UDS socket idle check period
#define UDS_IDLE_CHECK_PERIOD_US 1000000    // 1 second

#define UDS_PATH_TEMPLATE "/tmp/hashpipe_grpc.dp_%s.sock"

// Structure representing a Unix Domain Socket connection.
typedef struct uds_connection {
    char dp_name[16];
    int fd; // The connected socket
    char socket_path[128];
    struct timeval last_successful_write_time;
    struct uds_connection *next;
} uds_connection_t;

/**
 * @brief Gets the head of the list of Unix Domain Socket connections.
 *
 * @return Pointer to the head of the list of UDS connections.
 */
uds_connection_t* get_uds_connections_list_head();

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
void WriteImgSnapshotsToUds(DATA_PRODUCT dp, PACKET_HEADER *header, uint8_t *data);

/**
* @brief Sends a single-packet pulse-height snapshot over a Unix Domain Socket.
*
* @param dp The specific data product type (e.g., DP_PH_256_IMG).
* @param header Pointer to the packet's header.
* @param data Pointer to the pulse-height image data (512 bytes).
*/
void WritePHSnapshotsToUds(DATA_PRODUCT dp, PACKET_HEADER *header, uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif // _SNAPSHOT_H_
