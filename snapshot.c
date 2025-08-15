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
#include <poll.h>
#include <sys/time.h>

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
            (i < QUABO_PER_MODULE - 1) ? "," : "" 
        );
        if (n < 0 || n >= rem) return 0; p += n; rem -= n;
    }

    n = snprintf(p, rem, "}");
    if (n < 0 || n >= rem) return 0; p += n;

    return (p - dest);
}

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
        conn->fd = -1;
    }

    // Check for the socket file's existence
    struct stat buffer;
    if (stat(conn->socket_path, &buffer) != 0) {
        if (errno == ENOENT) {
            // This is expected if the server is down, so no warning is needed unless debugging
            //hashpipe_info(__FUNCTION__, "Socket file %s not found. Will retry.", conn->socket_path);
        }
        return; 
    }

    // Open the UDS in non-blocking streaming mode
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
    gettimeofday(&conn->last_successful_write_time, NULL); 
    conn->next = g_uds_connections;
    g_uds_connections = conn;
    hashpipe_info(__FUNCTION__, "Created UDS client manager for %s", conn->socket_path);
    return conn;
}

uds_connection_t* get_uds_connections_list_head(void) {
    return g_uds_connections;
}


static void WritePFFToUds(int module_id, DATA_PRODUCT dp, const char* json_doc, const void* image_data, size_t image_bytes) {
    const char* dp_name = uds_dp_to_str(dp);
    uds_connection_t* conn = get_uds_connection(dp_name);
    if (conn == NULL) return; // Should not happen

    // If not connected, attempt a single non-blocking connection.
    if (conn->fd < 0) {
        uds_connect(conn);
        // If the connection attempt fails, drop the frame and return immediately.
        // The next call to this function will try to connect again.
        if (conn->fd < 0) {
            return;
        }
    }

    // Health check
    struct pollfd pfd;
    pfd.fd = conn->fd;
    pfd.events = POLLOUT; // Check if the socket is writable

    int poll_ret = poll(&pfd, 1, 0); // 0-timeout for a non-blocking check

    if (poll_ret < 0) {
        // Poll itself failed
        hashpipe_error(__FUNCTION__, "UDS poll error on %s: %s. Closing fd.", conn->socket_path, strerror(errno));
        close(conn->fd);
        conn->fd = -1;
        return; // Drop frame
    }

    if (poll_ret > 0 && (pfd.revents & (POLLERR | POLLHUP))) {
        // The server has hung up or an error occurred. The socket is dead.
        hashpipe_warn(__FUNCTION__, "UDS connection to %s is broken (POLLERR/HUP). Closing fd.", conn->socket_path);
        close(conn->fd);
        conn->fd = -1;
        return; // Drop frame, will try to reconnect on next call
    }

    // Prepare message for writev
    struct iovec iov[4];

    // Part 1: 2-byte module ID in network byte order (big-endian)
    uint16_t net_module_id = htons((uint16_t)module_id);
    iov[0].iov_base = &net_module_id;
    iov[0].iov_len = sizeof(net_module_id);
    
    // Part 2: JSON header
    iov[1].iov_base = (void*)json_doc;
    iov[1].iov_len = strlen(json_doc);
    
    // Part 3: Separator
    char separator[] = "\n\n*";
    iov[2].iov_base = separator;
    iov[2].iov_len = 3;

    // Part 4: Binary image data
    iov[3].iov_base = (void*)image_data;
    iov[3].iov_len = image_bytes;

    ssize_t bytes_sent = writev(conn->fd, iov, 4);

    if (bytes_sent >= 0) {
        // Data sent successfully.
        gettimeofday(&conn->last_successful_write_time, NULL);
        return;
    }

    // If writev failed, handle the error without blocking.
    if (errno == EPIPE || errno == ECONNRESET || errno == EBADF) {
        // The server has closed the connection. Clean up our end.
        hashpipe_warn(__FUNCTION__, "UDS connection to %s lost (writev). Closing fd.", conn->socket_path);
        close(conn->fd);
        conn->fd = -1; // Mark as disconnected for the next attempt.
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // The socket's buffer is full. The server is alive but busy.
        hashpipe_warn(__FUNCTION__, "UDS socket for %s is busy. Dropping frame.", conn->socket_path);
    } else {
        // An unexpected error occurred. Close the connection to be safe.
        hashpipe_error(__FUNCTION__, "Unexpected UDS writev error on %s: %s. Closing fd.", conn->socket_path, strerror(errno));
        close(conn->fd);
        conn->fd = -1;
    }
    // In all error cases, we drop the frame and return immediately.
}


void WritePHSnapshotsToUds(DATA_PRODUCT dp, PACKET_HEADER *header, uint8_t *data) {
    if (!header || !data) return;
    char json_buffer[1024];

    // Determine data size based on data product
    size_t image_bytes = PIXELS_PER_IMAGE * bytes_per_pixel(dp);

    if (sprint_ph_snapshot_json(json_buffer, sizeof(json_buffer), header) > 0) {
        // Pass the dp and calculated size to the generic writer function
        WritePFFToUds(header->mod_num, dp, json_buffer, data, image_bytes);
    } else {
        hashpipe_error(__FUNCTION__, "Failed to sprint PH snapshot JSON for UDS");
    }
}

void WriteImgSnapshotsToUds(DATA_PRODUCT dp, PACKET_HEADER *header, uint8_t *data) {
    if (!header || !data) return;
    char json_buffer[4096];

    // Determine data size based on data product
    size_t image_bytes = QUABO_PER_MODULE * PIXELS_PER_IMAGE * bytes_per_pixel(dp);

    if (sprint_img_snapshot_json(json_buffer, sizeof(json_buffer), header) > 0) {
        // Pass the dp and calculated size to the generic writer function
        WritePFFToUds(header[0].mod_num, dp, json_buffer, data, image_bytes);
    } else {
        hashpipe_error(__FUNCTION__, "Failed to sprint Img snapshot JSON for UDS");
    }
}
