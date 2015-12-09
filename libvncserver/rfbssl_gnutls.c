/*
 * rfbssl_gnutls.c - Secure socket funtions (gnutls version)
 */

/*
 *  Copyright (C) 2011 Gernot Tenchio
 *
 *  This is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this software; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 *  USA.
 */

#include "rfbssl.h"
#include <gnutls/gnutls.h>
#include <errno.h>

static const char* const TLS_PRIORITY_STRING = "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-RSA:-DHE-RSA:-SHA1:%PROFILE_HIGH";

struct rfbssl_ctx {
    char peekbuf[2048];
    int peeklen;
    int peekstart;
    gnutls_session_t session;
    gnutls_certificate_credentials_t x509_cred;
};

void rfbssl_log_func(int level, const char *msg)
{
    rfbErr("SSL: %s", msg);
}

static void rfbssl_error(const char *msg, int e)
{
    rfbErr("%s: %s (%d)\n", msg, gnutls_strerror(e), e);
}

static int rfbssl_init_session(struct rfbssl_ctx *ctx, int fd)
{
    gnutls_session_t session;
    int ret;

    if (!(GNUTLS_E_SUCCESS == (ret = gnutls_init(&session, GNUTLS_SERVER)))) {
      rfbssl_error("gnutls_init", ret);
    } else if (!(GNUTLS_E_SUCCESS == (ret = gnutls_priority_set_direct(session, TLS_PRIORITY_STRING, NULL)))) {
      rfbssl_error("gnutls_priority_set_direct", ret);
    } else if (!(GNUTLS_E_SUCCESS == (ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, ctx->x509_cred)))) {
      rfbssl_error("gnutls_credentials_set", ret);
    } else {
      //gnutls_session_enable_compatibility_mode(session);
      gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(uintptr_t)fd);
      ctx->session = session;
    }
    return ret;
}

struct rfbssl_ctx *rfbssl_init_global(char *key, char *cert)
{
    int ret = GNUTLS_E_SUCCESS;
	struct rfbssl_ctx *ctx = malloc(sizeof(struct rfbssl_ctx));
	
	if (ctx == NULL) {
		ret = GNUTLS_E_MEMORY_ERROR;
	} else if (!(GNUTLS_E_SUCCESS == (ret = gnutls_certificate_allocate_credentials(&ctx->x509_cred)))) {
		rfbssl_error("gnutls_certificate_allocate_credentials", ret);
    } else if ((ret = gnutls_certificate_set_x509_trust_file(ctx->x509_cred, cert, GNUTLS_X509_FMT_PEM)) < 0) {
		rfbssl_error("gnutls_certificate_set_x509_trust_file", ret);
    } else if (!(GNUTLS_E_SUCCESS == (ret = gnutls_certificate_set_x509_key_file(ctx->x509_cred, cert, key, GNUTLS_X509_FMT_PEM)))) {
		rfbssl_error("gnutls_certificate_set_x509_key_file", ret);
    } else {
		gnutls_global_set_log_function(rfbssl_log_func);
		gnutls_global_set_log_level(1);
		/* newly allocated memory should be initialized, at least where it is important */
		ctx->peekstart = ctx->peeklen = 0;
		return ctx;
    }

	rfbssl_error(__func__, ret);
    free(ctx);
    return NULL;
}

int rfbssl_init(rfbClientPtr cl)
{
    int ret = -1;
    struct rfbssl_ctx *ctx;
    char *keyfile;
    if (!(keyfile = cl->screen->sslkeyfile)) {
		keyfile = cl->screen->sslcertfile;
	}

    if (NULL == (ctx = rfbssl_init_global(keyfile,  cl->screen->sslcertfile))) {

	/* */
    } else if (GNUTLS_E_SUCCESS != (ret = rfbssl_init_session(ctx, cl->sock))) {
	/* */
    } else {
		do {
			ret = gnutls_handshake(ctx->session);
		} while (ret != GNUTLS_E_SUCCESS && !gnutls_error_is_fatal(ret));
    }

    if (ret != GNUTLS_E_SUCCESS) {
		if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
			rfbErr("%s: alert %s\n", __func__, gnutls_alert_get_name(gnutls_alert_get(ctx->session)));
		}
		rfbssl_error(__func__, ret);
    } else {
		cl->sslctx = (rfbSslCtx *)ctx;
		rfbLog("%s protocol initialized\n", gnutls_protocol_get_name(gnutls_protocol_get_version(ctx->session)));
    }
    return ret;
}

static int rfbssl_do_read(rfbClientPtr cl, char *buf, int bufsize)
{
    struct rfbssl_ctx *ctx = (struct rfbssl_ctx *)cl->sslctx;
    int ret;

    while ((ret = gnutls_record_recv(ctx->session, buf, bufsize)) < 0) {
	if (ret == GNUTLS_E_AGAIN) {
	    /* continue */
	} else if (ret == GNUTLS_E_INTERRUPTED) {
	    /* continue */
	} else {
	    break;
	}
    }

    if (ret < 0) {
	rfbssl_error(__func__, ret);
	if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		rfbErr("%s: alert %s\n", __func__, gnutls_alert_get_name(gnutls_alert_get(ctx->session)));
	}
	errno = EIO;
	ret = -1;
    }

    return ret < 0 ? -1 : ret;
}

int rfbssl_write(rfbClientPtr cl, const char *buf, int bufsize)
{
    struct rfbssl_ctx *ctx = (struct rfbssl_ctx *)cl->sslctx;
    int ret;

    while ((ret = gnutls_record_send(ctx->session, buf, bufsize)) < 0) {
	if (ret == GNUTLS_E_AGAIN) {
	    /* continue */
	} else if (ret == GNUTLS_E_INTERRUPTED) {
	    /* continue */
	} else {
	    break;
	}
    }

    if (ret < 0)
	rfbssl_error(__func__, ret);

    return ret;
}

static void rfbssl_gc_peekbuf(struct rfbssl_ctx *ctx, int bufsize)
{
    if (ctx->peekstart) {
	int spaceleft = sizeof(ctx->peekbuf) - ctx->peeklen - ctx->peekstart;
	if (spaceleft < bufsize) {
	    memmove(ctx->peekbuf, ctx->peekbuf + ctx->peekstart, ctx->peeklen);
	    ctx->peekstart = 0;
	}
    }
}

static int __rfbssl_read(rfbClientPtr cl, char *buf, int bufsize, int peek)
{
    int ret = 0;
    struct rfbssl_ctx *ctx = (struct rfbssl_ctx *)cl->sslctx;

    rfbssl_gc_peekbuf(ctx, bufsize);

    if (ctx->peeklen) {
	/* If we have any peek data, simply return that. */
	ret = bufsize < ctx->peeklen ? bufsize : ctx->peeklen;
	memcpy (buf, ctx->peekbuf + ctx->peekstart, ret);
	if (!peek) {
	    ctx->peeklen -= ret;
	    if (ctx->peeklen != 0)
		ctx->peekstart += ret;
	    else
		ctx->peekstart = 0;
	}
    }

    if (ret < bufsize) {
	int n;
	/* read the remaining data */
	if ((n = rfbssl_do_read(cl, buf + ret, bufsize - ret)) <= 0) {
	    rfbErr("rfbssl_%s: %s error\n", __func__, peek ? "peek" : "read");
	    return n;
	}
	if (peek) {
	    memcpy(ctx->peekbuf + ctx->peekstart + ctx->peeklen, buf + ret, n);
	    ctx->peeklen += n;
	}
	ret += n;
    }

    return ret;
}

int rfbssl_read(rfbClientPtr cl, char *buf, int bufsize)
{
    return __rfbssl_read(cl, buf, bufsize, 0);
}

int rfbssl_peek(rfbClientPtr cl, char *buf, int bufsize)
{
    return __rfbssl_read(cl, buf, bufsize, 1);
}

int rfbssl_pending(rfbClientPtr cl)
{
    struct rfbssl_ctx *ctx = (struct rfbssl_ctx *)cl->sslctx;
    int ret = ctx->peeklen;

    if (ret <= 0)
	ret = gnutls_record_check_pending(ctx->session);

    return ret;
}

void rfbssl_destroy(rfbClientPtr cl)
{
    struct rfbssl_ctx *ctx = (struct rfbssl_ctx *)cl->sslctx;
    gnutls_bye(ctx->session, GNUTLS_SHUT_WR);
    gnutls_deinit(ctx->session);
    gnutls_certificate_free_credentials(ctx->x509_cred);
}
