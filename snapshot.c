// Contains functions for creating and sending filesystem and UDS snapshots.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <netinet/in.h> 

#include "snapshot.h"
#include "hashpipe.h"
#include "pff.h"
#include "databuf.h" 

// =====================================================================
// Unified JSON Header Creation Functions
// =====================================================================

/**
 * @brief Generates a fixed-size JSON string for a single-quabo PH snapshot.
 * This is the canonical function for creating PH snapshot headers for all data paths.
 * @return Number of bytes written to dest, or 0 on failure.
 */
static int sprint_ph_snapshot_json(char* dest, size_t size, PACKET_HEADER* head) {
    uint32_t pkt_nsec = head->pkt_nsec;
    if (pkt_nsec > 999999999) pkt_nsec = 999999999; // Clamp nanoseconds

    int n = snprintf(dest, size,
        "{ \"quabo_num\": %1u, \"pkt_num\": %10u, \"pkt_tai\": %4u, \"pkt_nsec\": %9u, \"tv_sec\": %10li, \"tv_usec\": %6li}",
        head->quabo_num,
        head->pkt_num,
        head->pkt_tai,
        pkt_nsec,
        head->tv_sec,
        head->tv_usec
    );

    if (n < 0 || n >= size) return 0;
    return n;
}

/**
 * @brief Generates a fixed-size JSON string for a four-quabo image snapshot.
 * This is the canonical function for creating image snapshot headers for all data paths.
 * @return Number of bytes written to dest, or 0 on failure.
 */
static int sprint_img_snapshot_json(char* dest, size_t size, PACKET_HEADER* head) {
    char* p = dest;
    size_t rem = size;
    int n;

    n = snprintf(p, rem, "{\n");
    if (n < 0 || n >= rem) return 0; p += n; rem -= n;

    for (int i = 0; i < QUABO_PER_MODULE; i++) {
        uint32_t pkt_nsec = head[i].pkt_nsec;
        if (pkt_nsec > 999999999) pkt_nsec = 999999999; // Clamp nanoseconds

        n = snprintf(p, rem,
            " \"quabo_%1u\": { \"pkt_num\": %10u, \"pkt_tai\": %4u, \"pkt_nsec\": %9u, \"tv_sec\": %10li, \"tv_usec\": %6li}%s\n",
            i,
            head[i].pkt_num,
            head[i].pkt_tai,
            pkt_nsec,
            head[i].tv_sec,
            head[i].tv_usec,
            (i < QUABO_PER_MODULE - 1) ? "," : "" // Standardized comma
        );
        if (n < 0 || n >= rem) return 0; p += n; rem -= n;
    }

    n = snprintf(p, rem, "}");
    if (n < 0 || n >= rem) return 0; p += n;

    return (p - dest);
}

// // Helper to write a single PH packet header to a JSON object in a file.
// static int write_ph_snapshot_header(FILE *f, PACKET_HEADER *dataHeader)
// {
//     if (dataHeader->pkt_nsec > 999999999)
//         dataHeader->pkt_nsec = 999999999;
//     fprintf(f,
//             "{ \"quabo_num\": %1u, \"pkt_num\": %10u, \"pkt_tai\": %4u, \"pkt_nsec\": %9u, \"tv_sec\": %10li, \"tv_usec\": %6li}",
//             dataHeader->quabo_num,
//             dataHeader->pkt_num,
//             dataHeader->pkt_tai,
//             dataHeader->pkt_nsec,
//             dataHeader->tv_sec,
//             dataHeader->tv_usec);
//     return 0;
// }
// // Helper to write four image packet headers to a JSON object in a file.
// int write_img_snapshot_header(FILE *f, PACKET_HEADER *dataHeader)
// {
//     fprintf(f, "{\n");
//     for (int i = 0; i < QUABO_PER_MODULE; i++)
//     {
//         if (dataHeader[i].pkt_nsec > 999999999)
//             dataHeader[i].pkt_nsec = 999999999;
//         fprintf(f,
//                 "   \"quabo_%1u\": { \"pkt_num\": %10u, \"pkt_tai\": %4u, \"pkt_nsec\": %9u, \"tv_sec\": %10li, \"tv_usec\": %6li}",
//                 i,
//                 dataHeader[i].pkt_num,
//                 dataHeader[i].pkt_tai,
//                 dataHeader[i].pkt_nsec,
//                 dataHeader[i].tv_sec,
//                 dataHeader[i].tv_usec);
//         if (i < QUABO_PER_MODULE - 1)
//         {
//             fprintf(f, ", ");
//         }
//         fprintf(f, "\n");
//     }
//     fprintf(f, "}");
//     return 0;
// }


// =====================================================================
// Filesystem Snapshot Functions (originally from net_thread.c)
// =====================================================================


// Writes a single-packet pulse-height snapshot to a file.
void WritePHSnapshots(FILE *fp, PACKET_HEADER *header, uint8_t *data) {
    char json_buffer[1024];

    // Create the JSON header in memory using the unified function
    if (sprint_ph_snapshot_json(json_buffer, sizeof(json_buffer), header) <= 0) {
        hashpipe_error(__FUNCTION__, "Failed to sprint PH snapshot JSON for filesystem");
        return;
    }

    // Write the PFF frame to the file
    // move the pointer to the beginning,
    // as we only need one pkt in the snapshot file.
    fseek(fp, 0, SEEK_SET);
    pff_start_json(fp);
    fputs(json_buffer, fp); // Write the generated JSON string
    pff_end_json(fp);
    pff_write_image(fp, PIXELS_PER_IMAGE * 2, data);
    fflush(fp);
    if (ftruncate(fileno(fp), ftell(fp)) < 0) {
        hashpipe_error(__FUNCTION__, "Failed to truncate PH snapshot file");
    }
    fsync(fileno(fp));
}


// write data into img snapshot file
void WriteImgSnapshots(FILE *fp, PACKET_HEADER *header, uint8_t *data) {
    char json_buffer[4096];

    // Create the JSON header in memory using the unified function
    if (sprint_img_snapshot_json(json_buffer, sizeof(json_buffer), header) <= 0) {
        hashpipe_error(__FUNCTION__, "Failed to sprint Img snapshot JSON for filesystem");
        return;
    }

    // Write the PFF frame to the file
    // move the pointer to the beginning,
    // as we only need one pkt in the snapshot file.
    fseek(fp, 0, SEEK_SET);
    pff_start_json(fp);
    fputs(json_buffer, fp); // Write the generated JSON string
    pff_end_json(fp);
    pff_write_image(fp, BYTES_PER_MODULE_FRAME, data);
    fflush(fp);
    if (ftruncate(fileno(fp), ftell(fp)) < 0) {
        hashpipe_error(__FUNCTION__, "Failed to truncate Img snapshot file");
    }
    fsync(fileno(fp));
}


// =====================================================================
// UDS Snapshot Functions
// =====================================================================

#define UDS_PATH_TEMPLATE "/tmp/hashpipe_grpc.dp_%s.sock"

typedef struct uds_connection {
    char dp_name[16];
    int fd; // The connected socket
    char socket_path[128];
    struct uds_connection *next;
} uds_connection_t;

static uds_connection_t *g_uds_connections = NULL;

const char* uds_dp_to_str(DATA_PRODUCT dp) {
    switch (dp) {
        case DP_BIT16_IMG: return "img16";
        case DP_BIT8_IMG:  return "img8";
        case DP_PH_256_IMG: return "ph256";
        case DP_PH_1024_IMG: return "ph1024";
        default: return "unknown";
    }
}

// Attempts a non-blocking connection to the server's socket.
static void uds_connect(uds_connection_t* conn) {
    if (conn->fd >= 0) {
        close(conn->fd);
    }
    conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (conn->fd < 0) return;
    int flags = fcntl(conn->fd, F_GETFL, 0);
    fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, conn->socket_path, sizeof(addr.sun_path) - 1);
    if (connect(conn->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            close(conn->fd);
            conn->fd = -1;
        }
    }
}

// Gets a connection manager for a given data product.
static uds_connection_t* get_uds_connection(const char* dp_name) {
    hashpipe_info(__FUNCTION__, "Getting UDS connection for %s", dp_name);
    uds_connection_t* conn;
    for (conn = g_uds_connections; conn != NULL; conn = conn->next) {
        if (strcmp(conn->dp_name, dp_name) == 0) {
            return conn;
        }
    }
    conn = (uds_connection_t*)malloc(sizeof(uds_connection_t));
    if (conn == NULL) {
        hashpipe_error(__FUNCTION__, "Failed to allocate UDS connection memory");
        return NULL;
    }
    strncpy(conn->dp_name, dp_name, sizeof(conn->dp_name) - 1);
    conn->dp_name[sizeof(conn->dp_name) - 1] = '\0';
    conn->fd = -1;
    snprintf(conn->socket_path, sizeof(conn->socket_path), UDS_PATH_TEMPLATE, dp_name);
    conn->next = g_uds_connections;
    g_uds_connections = conn;
    hashpipe_info(__FUNCTION__, "Created UDS client manager for %s", conn->socket_path);
    return conn;
}

static void WritePFFToUds(int module_id, DATA_PRODUCT dp, const char* json_doc, const void* image_data, size_t image_bytes) {
    const char* dp_name = uds_dp_to_str(dp);
    uds_connection_t* conn = get_uds_connection(dp_name);
    if (conn == NULL) return;

    if (conn->fd < 0) {
        uds_connect(conn);
        if (conn->fd < 0) return; // Connection failed, drop frame and retry next time.
    }

    // Prepare the 4 parts of the message for writev
    struct iovec iov[4];
    char separator[] = "\n\n*";
    
    // Part 1: 2-byte module ID in network byte order (big-endian)
    uint16_t net_module_id = htons((uint16_t)module_id);
    iov[0].iov_base = &net_module_id;
    iov[0].iov_len = sizeof(net_module_id);

    // Part 2: JSON header
    iov[1].iov_base = (void*)json_doc;
    iov[1].iov_len = strlen(json_doc);

    // Part 3: Separator
    iov[2].iov_base = separator;
    iov[2].iov_len = 3;

    // Part 4: Binary image data
    iov[3].iov_base = (void*)image_data;
    iov[3].iov_len = image_bytes;

    ssize_t bytes_sent = writev(conn->fd, iov, 4);

    if (bytes_sent < 0) {
        if (errno == EPIPE || errno == ECONNRESET) {
            hashpipe_warn(__FUNCTION__, "UDS connection to %s reset. Will reconnect.", conn->socket_path);
            close(conn->fd);
            conn->fd = -1;
        }
        // For EAGAIN/EWOULDBLOCK, silently drop frame.
    }
}


void WritePHSnapshotsToUds(PACKET_HEADER *header, uint8_t *data) {
    if (!header || !data) return;
    char json_buffer[1024];

    if (sprint_ph_snapshot_json(json_buffer, sizeof(json_buffer), header) > 0) {
        WritePFFToUds(header->mod_num, DP_PH_256_IMG, json_buffer, data, PIXELS_PER_IMAGE * 2);
    } else {
        hashpipe_error(__FUNCTION__, "Failed to sprint PH snapshot JSON for UDS");
    }
}

void WriteImgSnapshotsToUds(PACKET_HEADER *header, uint8_t *data) {
    if (!header || !data) return;
    char json_buffer[4096];

    if (sprint_img_snapshot_json(json_buffer, sizeof(json_buffer), header) > 0) {
        WritePFFToUds(header[0].mod_num, DP_BIT16_IMG, json_buffer, data, BYTES_PER_MODULE_FRAME);
    } else {
        hashpipe_error(__FUNCTION__, "Failed to sprint Img snapshot JSON for UDS");
    }
}
