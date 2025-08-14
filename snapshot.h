#ifndef _SNAPSHOT_H_
#define _SNAPSHOT_H_

#include <stdio.h>
#include <stdint.h>
#include "databuf.h" 

#ifdef __cplusplus
extern "C" {
#endif

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
 * @param header Pointer to an array of 4 PACKET_HEADER structs.
 * @param data Pointer to the assembled image data (2048 bytes).
 */
void WriteImgSnapshotsToUds(PACKET_HEADER *header, uint8_t *data);

/**
 * @brief Sends a single-packet pulse-height snapshot over a Unix Domain Socket.
 *
 * @param header Pointer to the packet's header.
 * @param data Pointer to the pulse-height image data (512 bytes).
 */
void WritePHSnapshotsToUds(PACKET_HEADER *header, uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif // _SNAPSHOT_H_
