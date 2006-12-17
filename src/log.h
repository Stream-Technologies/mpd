
/*
 * log.h
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _LG_H_
#define	_LG_H_

/*
 * DEFINITIONS
 */

  enum
  {
    LG_I_ALWAYS = 0,
    LG_I_BUND,
    LG_I_LINK,
    LG_I_CHAT,
    LG_I_CHAT2,
    LG_I_IFACE,
    LG_I_IFACE2,
    LG_I_LCP,
    LG_I_LCP2,
    LG_I_AUTH,
    LG_I_IPCP,
    LG_I_IPCP2,
    LG_I_IPV6CP,
    LG_I_IPV6CP2,
    LG_I_CCP,
    LG_I_CCP2,
    LG_I_CCP3,
    LG_I_ECP,
    LG_I_ECP2,
    LG_I_FSM,
    LG_I_ECHO,
    LG_I_PHYS,
    LG_I_PHYS2,
    LG_I_FRAME,
    LG_I_PPTP,
    LG_I_PPTP2,
    LG_I_PPTP3,
    LG_I_RADIUS,
    LG_I_RADIUS2,
    LG_I_CONSOLE
  };

/* Definition of log options */

  #define LG_BUND		(1 << LG_I_BUND)
  #define LG_LINK		(1 << LG_I_LINK)
  #define LG_CHAT		(1 << LG_I_CHAT)
  #define LG_CHAT2		(1 << LG_I_CHAT2)
  #define LG_IFACE		(1 << LG_I_IFACE)
  #define LG_IFACE2		(1 << LG_I_IFACE2)
  #define LG_LCP		(1 << LG_I_LCP)
  #define LG_LCP2		(1 << LG_I_LCP2)
  #define LG_AUTH		(1 << LG_I_AUTH)
  #define LG_IPCP		(1 << LG_I_IPCP)
  #define LG_IPCP2		(1 << LG_I_IPCP2)
  #define LG_IPV6CP		(1 << LG_I_IPV6CP)
  #define LG_IPV6CP2		(1 << LG_I_IPV6CP2)
  #define LG_CCP		(1 << LG_I_CCP)
  #define LG_CCP2		(1 << LG_I_CCP2)
  #define LG_CCP3		(1 << LG_I_CCP3)
  #define LG_ECP		(1 << LG_I_ECP)
  #define LG_ECP2		(1 << LG_I_ECP2)
  #define LG_FSM		(1 << LG_I_FSM)
  #define LG_ECHO		(1 << LG_I_ECHO)
  #define LG_PHYS		(1 << LG_I_PHYS)
  #define LG_PHYS2		(1 << LG_I_PHYS2)
  #define LG_FRAME		(1 << LG_I_FRAME)
  #define LG_PPTP		(1 << LG_I_PPTP)
  #define LG_PPTP2		(1 << LG_I_PPTP2)
  #define LG_PPTP3		(1 << LG_I_PPTP3)
  #define LG_RADIUS		(1 << LG_I_RADIUS)
  #define LG_RADIUS2		(1 << LG_I_RADIUS2)
  #define LG_CONSOLE		(1 << LG_I_CONSOLE)
  #define LG_ALWAYS		(1 << LG_I_ALWAYS)

  #define LG_ERR		(LG_ALWAYS)

/* Default options at startup */

  #define LG_DEFAULT_OPT	(0			\
				| LG_BUND		\
				| LG_LINK		\
			        | LG_IFACE		\
			        | LG_CONSOLE		\
			        | LG_CHAT		\
			        | LG_LCP		\
			        | LG_IPCP		\
			        | LG_IPV6CP		\
			        | LG_CCP		\
			        | LG_ECP		\
			        | LG_AUTH		\
			        | LG_RADIUS		\
			        | LG_FSM		\
			        | LG_PHYS		\
			        | LG_PPTP		\
				)

  #define Log(lev, args)	do {				\
				  if (gLogOptions & (lev))	\
				    LogPrintf args;		\
				} while (0)			\

  #define LogDepr(name, old, new) \
    Log(LG_ERR, ("[%s] '%s' is deprecated, use '%s' instead", name, old, new));
/*
 * VARIABLES
 */

  extern int	gLogOptions;
#ifdef SYSLOG_FACILITY
  extern char	gSysLogIdent[32];
#endif

/*
 * FUNCTIONS
 */

  extern int	LogOpen(void);
  extern void	LogClose(void);
  extern void	LogPrintf(const char *fmt, ...) __printflike(1, 2);
  extern void	vLogPrintf(const char *fmt, va_list args);
  extern void	LogStdout(const char *fmt, ...) __printflike(1, 2);
  extern int	LogCommand(int ac, char *av[], void *arg);
  extern void	LogDumpBuf(int lev, const u_char *buf,
		  int len, const char *fmt, ...) __printflike(4, 5);
  extern void	LogDumpBp(int lev, Mbuf bp, const char *fmt, ...)
			__printflike(3, 4);
  extern void	Perror(const char *fmt, ...) __printflike(1, 2);

#endif

