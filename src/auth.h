
/*
 * auth.h
 *
 * Written by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#ifndef _AUTH_H_
#define	_AUTH_H_

#include "timer.h"
#include "ppp.h"
#include "pap.h"
#include "chap.h"
#include "eap.h"
#include "radius.h"

#include <pwd.h>
#include <opie.h>
#include <utmp.h>
  
/*
 * DEFINITIONS
 */

  #define AUTH_RETRIES		3

  #define AUTH_MSG_WELCOME	"Welcome\r\n"
  #define AUTH_MSG_INVALID	"Login incorrect\r\n"
  #define AUTH_MSG_BAD_PACKET	"Incorrectly formatted packet\r\n"
  #define AUTH_MSG_NOT_ALLOWED	"Login not allowed for this account\r\n"
  #define AUTH_MSG_NOT_EXPECTED	"Unexpected packet\r\n"
  #define AUTH_MSG_ACCT_DISAB	"Account disabled\r\n"
  #define AUTH_MSG_RESTR_HOURS	"Login hours restricted\r\n"

  #define AUTH_PEER_TO_SELF	0
  #define AUTH_SELF_TO_PEER	1

  #define AUTH_FAIL_INVALID_LOGIN	0
  #define AUTH_FAIL_ACCT_DISABLED	1
  #define AUTH_FAIL_NO_PERMISSION	2
  #define AUTH_FAIL_RESTRICTED_HOURS	3
  #define AUTH_FAIL_INVALID_PACKET	4
  #define AUTH_FAIL_NOT_EXPECTED	5
  
  #define AUTH_STATUS_UNDEF		0
  #define AUTH_STATUS_FAIL		1
  #define AUTH_STATUS_SUCCESS		2
  
  #define AUTH_PW_HASH_NONE		0
  #define AUTH_PW_HASH_NT		1
  
  #define AUTH_ACCT_START		1
  #define AUTH_ACCT_STOP		2
  #define AUTH_ACCT_UPDATE		3
  
  #define MPPE_POLICY_NONE	0
  #define MPPE_POLICY_ALLOWED	1
  #define MPPE_POLICY_REQUIRED	2

  #define MPPE_TYPE_0BIT	0	/* No encryption required */
  #define MPPE_TYPE_40BIT	2
  #define MPPE_TYPE_128BIT	4
  #define MPPE_TYPE_56BIT	8
  
  /* Configuration options */
  enum {
    AUTH_CONF_RADIUS_AUTH = 1,
    AUTH_CONF_RADIUS_ACCT,
    AUTH_CONF_INTERNAL,
    AUTH_CONF_SYSTEM,
    AUTH_CONF_OPIE,
    AUTH_CONF_MAX_LOGINS,
    AUTH_CONF_UTMP_WTMP,
  };  

  /* max. length of acl rule, */
  #define ACL_LEN	256

  struct acl {		/* List of ACLs received from auth */
    unsigned short number;		/* ACL number given by auth server */
    unsigned short real_number;	/* ACL number allocated my mpd */
    char rule[ACL_LEN]; /* Text of ACL */
    struct acl *next;
  };

  struct authparams {
    char		authname[AUTH_MAX_AUTHNAME];
    char		password[AUTH_MAX_PASSWORD];

    struct papparams	pap;

    struct u_range	range;		/* IP range allowed to user */
    u_int		range_valid:1;  /* range is valid */
    struct in_addr	mask;		/* IP Netmask */

    unsigned long	class;      	/* Class */
    char		*eapmsg;	/* EAP Msg for forwarding to RADIUS server */
    int			eapmsg_len;
    char		*state;		/* copy of the state attribute, needed for accounting */
    int			state_len;

    struct acl		*acl_rule;
    struct acl		*acl_pipe;
    struct acl		*acl_queue;
    struct acl		*acl_table;

    unsigned long	mtu;			/* MTU */
    unsigned long	session_timeout;	/* Session-Timeout */
    unsigned long	idle_timeout;		/* Idle-Timeout */
    unsigned long	acct_update;		/* interval for accouting updates */
    char		*msdomain;		/* Microsoft domain */
    short		n_routes;
    struct ifaceroute	routes[IFACE_MAX_ROUTES];

    char		peeraddr[64];	/* hr representation of the peer address */
    char		callingnum[64];	/* hr representation of the calling number */
    char		callednum[64];	/* hr representation of the called number */

    int			authentic;	/* wich backend was used */

    struct linkstats	prev_stats;	/* Previous link statistics */

    struct {
      int	policy;			/* MPPE_POLICY_* */
      int	types;			/* MPPE_TYPE_*BIT bitmask */
      int	has_nt_hash;
      u_char	nt_hash[16];		/* NT-Hash */
      int	has_lm_hash;
      u_char	lm_hash[16];		/* LM-Hash */
      int	has_keys;
      u_char	nt_hash_hash[16];	/* NT-Hash-Hash */
      /* Keys when using MS-CHAPv2 or EAP */
      u_char	xmit_key[MPPE_KEY_LEN];	/* xmit start key */
      u_char	recv_key[MPPE_KEY_LEN];	/* recv start key */
    } msoft;
  };

  struct authconf {
    struct radiusconf	radius;		/* RADIUS configuration */
    char		authname[AUTH_MAX_AUTHNAME];	/* Configured username */
    char		password[AUTH_MAX_PASSWORD];	/* Configured password */
    int			acct_update;
    int			acct_update_lim_recv;
    int			acct_update_lim_xmit;
    int			timeout;	/* Authorization timeout in seconds */
    struct optinfo	options;	/* Configured options */
  };
  typedef struct authconf	*AuthConf;

  /* State of authorization process during authorization phase,
   * contains params set by the auth-backend */
  struct auth {
    u_short		peer_to_self;	/* What I need from peer */
    u_short		self_to_peer;	/* What peer needs from me */
    struct pppTimer	timer;		/* Max time to spend doing auth */
    struct pppTimer	acct_timer;	/* Timer for accounting updates */
    struct papinfo	pap;		/* PAP state */
    struct chapinfo	chap;		/* CHAP state */
    struct eapinfo	eap;		/* EAP state */
    struct paction	*thread;	/* async auth thread */
    struct paction	*acct_thread;	/* async accounting auth thread */
    struct authconf	conf;		/* Auth backends, RADIUS, etc. */
    struct authparams	params;		/* params to pass to from auth backend */
  };
  typedef struct auth	*Auth;

  struct radiusconf	radius;			/* RADIUS configuration */
  /* Interface between the auth-backend (secret file, RADIUS, etc.)
   * and Mpd's internal structs.
   */
  struct authdata {
    Link		lnk;		/* a copy of the link */
    struct authconf	conf;		/* a copy of bundle's authconf */
    int			proto;		/* wich proto are we using, PAP, CHAP, ... */
    u_int		id;		/* Actual, packet id */    
    u_int		code;		/* Proto specific code */
    u_short		status;
    int			why_fail;
    u_char		ack_mesg[128];
    char		*reply_message;	/* Text wich may displayed to the user */
    char		*mschap_error;	/* MSCHAP Error Message */
    char		*mschapv2resp;	/* Response String for MSCHAPv2 */
    void		(*finish)(struct authdata *auth); /* Finish handler */
    int			acct_type;	/* Accounting type, Start, Stop, Update */
    struct {
      struct rad_handle	*handle;	/* the RADIUS handle */
    } radius;
    struct {
      struct opie	data;
    } opie;
    struct {		/* informational (read-only) data needed for e.g. accouting */
      struct in_addr	peer_addr;	/* currently assigned IP-Address of the client */
      short		n_links;	/* number of links in the bundle */
      char		msession_id[AUTH_MAX_SESSIONID]; /* multy-session-id */
      char		session_id[AUTH_MAX_SESSIONID];	/* session-id */
      char		lnkname[LINK_MAX_NAME];	/* name of the link */
      struct linkstats	stats;		/* Current link statistics */
    } info;
    struct authparams	params;		/* params to pass to from auth backend */
  };
  typedef struct authdata	*AuthData;
  
  extern const struct cmdtab AuthSetCmds[];

/*
 * GLOBAL VARIABLES
 */
  extern const u_char	gMsoftZeros[32];
  extern int		gMaxLogins;	/* max number of concurrent logins per user */

/*
 * FUNCTIONS
 */

  extern void		AuthInit(void);
  extern void		AuthStart(void);
  extern void		AuthStop(void);
  extern void		AuthInput(int proto, Mbuf bp);
  extern void		AuthOutput(int proto, u_int code, u_int id,
			  const u_char *ptr, int len, int add_len, 
			  u_char eap_type);
  extern void		AuthFinish(int which, int ok);
  extern void		AuthCleanup(void);
  extern int		AuthStat(int ac, char *av[], void *arg);
  extern void		AuthAccountStart(int type);
  extern AuthData	AuthDataNew(void);
  extern void		AuthDataDestroy(AuthData auth);
  extern int		AuthGetData(AuthData auth, int complain);
  extern void		AuthAsyncStart(AuthData auth);
  extern const char	*AuthFailMsg(AuthData auth, int alg);
  extern const char	*AuthStatusText(int status);
  extern const char	*AuthMPPEPolicyname(int policy);
  extern const char	*AuthMPPETypesname(int types);

  extern void		authparamsInit(struct authparams *ap);
  extern void		authparamsCopy(struct authparams *src, struct authparams *dst);
  extern void		authparamsDestroy(struct authparams *ap);

#endif
