#ifndef _NET_THREAD_H_
#define _NET_THREAD_H_

// PKTSOCK Params
// (These should be only changed with caution as it need to change with MMAP)
#define PKTSOCK_BYTES_PER_FRAME (1024)
#define PKTSOCK_FRAMES_PER_BLOCK (4096)
#define PKTSOCK_NBLOCKS (512)
#define PKTSOCK_NFRAMES (PKTSOCK_FRAMES_PER_BLOCK * PKTSOCK_NBLOCKS)


#endif /* _NET_THREAD_H_ */
