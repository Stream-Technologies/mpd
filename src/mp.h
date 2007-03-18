
/*
 * mp.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _MP_H_
#define _MP_H_

#include <sys/types.h>
#include "fsm.h"
#include "mbuf.h"

/*
 * DEFINITIONS
 */

/* Discriminators */

  #define MAX_DISCRIM		50

  #define DISCRIM_CLASS_NULL	0
  #define DISCRIM_CLASS_LOCAL	1
  #define DISCRIM_CLASS_IPADDR	2
  #define DISCRIM_CLASS_802_1	3
  #define DISCRIM_CLASS_MAGIC	4
  #define DISCRIM_CLASS_PSN	5

  struct discrim {
    u_char	len;
    u_char	class;
    u_char	bytes[MAX_DISCRIM];
  };
  typedef struct discrim	*Discrim;

/* Bounds on things */

  #define MP_MIN_MRRU		LCP_DEFAULT_MRU		/* Per RFC 1990 */
  #define MP_MAX_MRRU		1600
  #define MP_DEFAULT_MRRU	1600

/* LCP codes acceptable to transmit over the virtual link */

  #define MP_LCP_CODE_OK(c)	((c) >= CODE_CODEREJ && (c) <= CODE_ECHOREP)

/* Multi-link configuration */

  struct mpstate {
    u_short		self_mrru;		/* My MRRU size */
    u_short		peer_mrru;		/* His MRRU size */
    u_int		self_short_seq:1;	/* I expect short headers */
    u_int		peer_short_seq:1;	/* He wants short headers */
  };
  typedef struct mpstate	*MpState;

/*
 * FUNCTIONS
 */

  extern void	MpInit(Bund b, Link l);
  extern int	MpStat(int ac, char *av[], void *arg);
  extern void	MpSetDiscrim(void);
  extern int	MpDiscrimEqual(Discrim dis1, Discrim dis2);
  extern char *	MpDiscrimText(Discrim dis);

#endif

