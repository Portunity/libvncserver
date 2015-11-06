#ifndef _RFB_CRYPTO_H
#define _RFB_CRYPTO_H 1

#ifdef WIN32
#include <sys/types.h>
struct iovec {
	void* iov_base;
	size_t iov_len;
};
#else
#include <sys/uio.h>
#endif


#define SHA1_HASH_SIZE 20
#define MD5_HASH_SIZE 16

void digestmd5(const struct iovec *iov, int iovcnt, void *dest);
void digestsha1(const struct iovec *iov, int iovcnt, void *dest);

#endif
