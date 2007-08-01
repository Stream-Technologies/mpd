
/*
 * command.c
 *
 * Written by Toshiharu OHNO <tony-o@iij.ad.jp>
 * Copyright (c) 1993, Internet Initiative Japan, Inc. All rights reserved.
 * See ``COPYRIGHT.iij''
 * 
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1995-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "console.h"
#include "web.h"
#include "command.h"
#include "ccp.h"
#include "iface.h"
#include "radius.h"
#include "bund.h"
#include "link.h"
#include "lcp.h"
#include "nat.h"
#include "ipcp.h"
#include "ip.h"
#include "devices.h"
#include "netgraph.h"
#include "custom.h"
#include "ngfunc.h"
#include "util.h"

/*
 * DEFINITIONS
 */

  struct layer {
    const char	*name;
    void	(*opener)(Context ctx);
    void	(*closer)(Context ctx);
    const char	*desc;
  };
  typedef struct layer	*Layer;

  #define DEFAULT_OPEN_LAYER	"link"

  /* Set menu options */
  enum {
    SET_ENABLE,
    SET_DISABLE,
    SET_RULE,
    SET_QUEUE,
    SET_PIPE,
    SET_TABLE,
  };


/*
 * INTERNAL FUNCTIONS
 */

  /* Commands */
  static int	ShowVersion(Context ctx, int ac, char *av[], void *arg);
  static int	ShowLayers(Context ctx, int ac, char *av[], void *arg);
  static int	ShowTypes(Context ctx, int ac, char *av[], void *arg);
  static int	ShowSummary(Context ctx, int ac, char *av[], void *arg);
  static int	ShowEvents(Context ctx, int ac, char *av[], void *arg);
  static int	ShowGlobal(Context ctx, int ac, char *av[], void *arg);
  static int	OpenCommand(Context ctx, int ac, char *av[], void *arg);
  static int	CloseCommand(Context ctx, int ac, char *av[], void *arg);
  static int	LoadCommand(Context ctx, int ac, char *av[], void *arg);
  static int	ExitCommand(Context ctx, int ac, char *av[], void *arg);
  static int	QuitCommand(Context ctx, int ac, char *av[], void *arg);
  static int	NullCommand(Context ctx, int ac, char *av[], void *arg);
  static int	GlobalSetCommand(Context ctx, int ac, char *av[], void *arg);
  static int	SetDebugCommand(Context ctx, int ac, char *av[], void *arg);

  /* Other stuff */
  static int	DoCommandTab(Context ctx, CmdTab cmdlist, int ac, char *av[]);
  static Layer	GetLayer(const char *name);

/*
 * INTERNAL VARIABLES
 */

  static int	exitflag;

  const struct cmdtab GlobalSetCmds[] = {
    { "enable [opt ...]", 		"Enable option" ,
       	GlobalSetCommand, NULL, (void *) SET_ENABLE },
    { "disable [opt ...]", 		"Disable option" ,
       	GlobalSetCommand, NULL, (void *) SET_DISABLE },
    { "startrule num", 			"Initial ipfw rule number" ,
       	GlobalSetCommand, NULL, (void *) SET_RULE },
    { "startqueue num", 		"Initial ipfw queue number" ,
       	GlobalSetCommand, NULL, (void *) SET_QUEUE },
    { "startpipe num",			"Initial ipfw pipe number" ,
       	GlobalSetCommand, NULL, (void *) SET_PIPE },
    { "starttable num", 		"Initial ipfw table number" ,
       	GlobalSetCommand, NULL, (void *) SET_TABLE },
    { NULL },
  };

  static const struct confinfo	gGlobalConfList[] = {
    { 0,	GLOBAL_CONF_TCPWRAPPER,	"tcp-wrapper"	},
    { 0,	0,			NULL		},
  };

  static const struct cmdtab ShowCommands[] = {
    { "bundle [name]",			"Bundle status",
	BundStat, AdmitBund, NULL },
    { "repeater [name]",		"Repeater status",
	RepStat, AdmitRep, NULL },
    { "ccp",				"CCP status",
	CcpStat, AdmitBund, NULL },
    { "ecp",				"ECP status",
	EcpStat, AdmitBund, NULL },
    { "eap",				"EAP status",
	EapStat, AdmitBund, NULL },
    { "events",				"Current events",
	ShowEvents, NULL, NULL },
    { "ipcp",				"IPCP status",
	IpcpStat, AdmitBund, NULL },
    { "ipv6cp",				"IPV6CP status",
	Ipv6cpStat, AdmitBund, NULL },
    { "iface",				"Interface status",
	IfaceStat, AdmitBund, NULL },
    { "routes",				"IP routing table",
	IpShowRoutes, NULL, NULL },
    { "layers",				"Layers to open/close",
	ShowLayers, NULL, NULL },
    { "phys",				"Physical device status",
	PhysStat, AdmitPhys, NULL },
    { "link",				"Link status",
	LinkStat, AdmitLink, NULL },
    { "auth",				"Auth status",
	AuthStat, AdmitLink, NULL },
    { "radius",				"RADIUS status",
	RadStat, AdmitLink, NULL },
    { "lcp",				"LCP status",
	LcpStat, AdmitLink, NULL },
    { "nat",				"NAT status",
	NatStat, AdmitLink, NULL },
    { "mem",				"Memory map",
	MemStat, NULL, NULL },
    { "mp",				"Multi-link status",
	MpStat, AdmitBund, NULL },
    { "console",			"Console status",
	ConsoleStat, NULL, NULL },
    { "web",				"Web status",
	WebStat, NULL, NULL },
    { "global",				"Global settings",
	ShowGlobal, NULL, NULL },
    { "types",				"Supported device types",
	ShowTypes, NULL, NULL },
    { "version",			"Version string",
	ShowVersion, NULL, NULL },
    { "summary",			"Daemon status summary",
	ShowSummary, NULL, NULL },
    { NULL },
  };

  static const struct cmdtab SetCommands[] = {
    { "bundle ...",			"Bundle specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) BundSetCmds },
    { "repeater ...",			"Repeater specific stuff",
	CMD_SUBMENU, AdmitRep, (void *) RepSetCmds },
    { "link ...",			"Link specific stuff",
	CMD_SUBMENU, AdmitLink, (void *) LinkSetCmds },
    { "phys ...",			"Phys specific stuff",
	CMD_SUBMENU, AdmitPhys, (void *) PhysSetCmds },
    { "iface ...",			"Interface specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) IfaceSetCmds },
    { "ipcp ...",			"IPCP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) IpcpSetCmds },
    { "ipv6cp ...",			"IPV6CP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) Ipv6cpSetCmds },
    { "ccp ...",			"CCP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) CcpSetCmds },
    { "ecp ...",			"ECP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) EcpSetCmds },
    { "eap ...",			"EAP specific stuff",
	CMD_SUBMENU, AdmitBund, (void *) EapSetCmds },
    { "auth ...",			"Auth specific stuff",
	CMD_SUBMENU, AdmitLink, (void *) AuthSetCmds },
    { "radius ...",			"RADIUS specific stuff",
	CMD_SUBMENU, AdmitLink, (void *) RadiusSetCmds },
    { "console ...",			"Console specific stuff",
	CMD_SUBMENU, NULL, (void *) ConsoleSetCmds },
    { "web ...",			"Web specific stuff",
	CMD_SUBMENU, NULL, (void *) WebSetCmds },
    { "global ...",			"Global settings",
	CMD_SUBMENU, NULL, (void *) GlobalSetCmds },
#ifdef USE_NG_NETFLOW
    { "netflow ...", 			"NetFlow settings",
	CMD_SUBMENU, NULL, (void *) NetflowSetCmds },
#endif
    { "nat ...", 			"Nat settings",
	CMD_SUBMENU, NULL, (void *) NatSetCmds },
    { "debug level",			"Set netgraph debug level",
	SetDebugCommand, NULL, NULL },
#define _WANT_DEVICE_CMDS
#include "devices.h"
    { NULL },
  };

  const struct cmdtab gCommands[] = {
    { "new bundle link ...",		"Create new bundle",
    	BundCreateCmd, NULL, NULL },
    { "rnew repeater link1 link2",	"Create new repeater",
    	RepCreateCmd, NULL, NULL },
    { "bundle [name]",			"Choose/list bundles",
	BundCommand, NULL, NULL },
    { "msession [msesid]",		"Choose link by multy-session-id",
	MSessionCommand, NULL, NULL },
    { "repeater [name]",		"Choose/list repeaters",
	RepCommand, NULL, NULL },
    { "custom ...",			"Custom stuff",
	CMD_SUBMENU, NULL, (void *) CustomCmds },
    { "link [name]",			"Choose link",
	LinkCommand, NULL, NULL },
    { "session [sesid]",		"Choose link by session-id",
	SessionCommand, NULL, NULL },
    { "phys [name]",			"Choose phys",
	PhysCommand, NULL, NULL },
    { "open [layer]",			"Open a layer",
	OpenCommand, AdmitLink, NULL },
    { "close [layer]",			"Close a layer",
	CloseCommand, AdmitLink, NULL },
    { "load label",			"Read from config file",
	LoadCommand, NULL, NULL },
    { "set ...",			"Set parameters",
	CMD_SUBMENU, NULL, (void *) SetCommands },
    { "show ...",			"Show status",
	CMD_SUBMENU, NULL, (void *) ShowCommands },
    { "exit",				"Exit console",
	ExitCommand, NULL, NULL },
    { "null",				"Do nothing",
	NullCommand, NULL, NULL },
    { "log [+/-opt ...]",		"Set/view log options",
	LogCommand, NULL, NULL },
    { "quit",				"Quit program",
	QuitCommand, NULL, NULL },
    { "help ...",			"Help on any command",
	HelpCommand, NULL, NULL },
    { NULL },
  };



/*
 * Layers
 */

  struct layer	gLayers[] = {
    { "iface",
      IfaceOpenCmd,
      IfaceCloseCmd,
      "System interface"
    },
    { "ipcp",
      IpcpOpenCmd,
      IpcpCloseCmd,
      "IPCP: IP control protocol"
    },
    { "ipv6cp",
      Ipv6cpOpenCmd,
      Ipv6cpCloseCmd,
      "IPV6CP: IPv6 control protocol"
    },
    { "ccp",
      CcpOpenCmd,
      CcpCloseCmd,
      "CCP: compression ctrl prot."
    },
    { "ecp",
      EcpOpenCmd,
      EcpCloseCmd,
      "ECP: encryption ctrl prot."
    },
    { "bund",
      BundOpenCmd,
      BundCloseCmd,
      "Multilink bundle"
    },
    { "link",
      LinkOpenCmd,
      LinkCloseCmd,
      "Link layer"
    },
    { "phys",
      PhysOpenCmd,
      PhysCloseCmd,
      "Physical link layer"
    },
  };

  #define NUM_LAYERS	(sizeof(gLayers) / sizeof(*gLayers))

/*
 * DoCommand()
 *
 * Executes command. Returns TRUE if user wants to quit.
 */

int
DoCommand(Context ctx, int ac, char *av[], const char *file, int line)
{
  int	rtn;
  char	filebuf[100];
  
  exitflag = FALSE;
  rtn = DoCommandTab(ctx, gCommands, ac, av);

  /* Bad usage? */
  if (rtn < 0) {
    if (file) {
	snprintf(filebuf,sizeof(filebuf),"%s:%d: ", file, line);
	HelpCommand(ctx, ac, av, filebuf);
    } else {
	HelpCommand(ctx, ac, av, NULL);
    }
  }
  
  return(exitflag);
}

/*
 * DoCommandTab()
 *
 * Execute command from given command menu
 */

static int
DoCommandTab(Context ctx, CmdTab cmdlist, int ac, char *av[])
{
  CmdTab	cmd;
  int		rtn = 0;

  /* Huh? */
  if (ac <= 0)
    return(-1);

  /* Find command */
  if (FindCommand(cmdlist, av[0], &cmd))
    return(-1);

  /* Check command admissibility */
  if (cmd->admit && !(cmd->admit)(ctx, cmd))
    return(0);

  /* Find command and either execute or recurse into a submenu */
  if (cmd->func == CMD_SUBMENU)
    rtn = DoCommandTab(ctx, (CmdTab) cmd->arg, ac - 1, av + 1);
  else if (cmd->func == CMD_UNIMPL)
    Log(LG_ERR, ("command '%s' is not implemented", av[0]));
  else
    rtn = (cmd->func)(ctx, ac - 1, av + 1, cmd->arg);

  return(rtn);
}

/*
 * FindCommand()
 */

int
FindCommand(CmdTab cmds, char *str, CmdTab *cmdp)
{
  int		nmatch;
  int		len = strlen(str);

  for (nmatch = 0; cmds->name; cmds++) {
    if (cmds->name && !strncmp(str, cmds->name, len)) {
      *cmdp = cmds;
      nmatch++;
    }
  }
  switch (nmatch) {
    case 0:
      return(-1);
    case 1:
      return(0);
    default:
      return(-2);
  }
}

/********** COMMANDS **********/


/*
 * GlobalSetCommand()
 */

static int
GlobalSetCommand(Context ctx, int ac, char *av[], void *arg) 
{
    int val;

  if (ac == 0)
    return(-1);

  switch ((intptr_t)arg) {
    case SET_ENABLE:
      EnableCommand(ac, av, &gGlobalConf.options, gGlobalConfList);
      break;

    case SET_DISABLE:
      DisableCommand(ac, av, &gGlobalConf.options, gGlobalConfList);
      break;

    case SET_RULE:
	if (rule_pool) 
	    Log(LG_ERR, ("Rule pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>=65535)
		Log(LG_ERR, ("Incorrect rule number"));
	    else
		rule_pool_start = val;
	}
      break;

    case SET_QUEUE:
	if (queue_pool) 
	    Log(LG_ERR, ("Queue pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>=65535)
		Log(LG_ERR, ("Incorrect queue number"));
	    else
		queue_pool_start = val;
	}
      break;

    case SET_PIPE:
	if (rule_pool) 
	    Log(LG_ERR, ("Pipe pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>=65535)
		Log(LG_ERR, ("Incorrect rule number"));
	    else
		pipe_pool_start = val;
	}
      break;

    case SET_TABLE:
	if (rule_pool) 
	    Log(LG_ERR, ("Table pool is not empty. Impossible to set initial number"));
	else {
	    val = atoi(*av);
	    if (val <= 0 || val>127) /* table 0 is usually possible but we deny it */
		Log(LG_ERR, ("Incorrect rule number"));
	    else
		table_pool_start = val;
	}
      break;

    default:
      return(-1);
  }

  return 0;
}

/*
 * HelpCommand()
 */

int
HelpCommand(Context ctx, int ac, char *av[], void *arg)
{
  int		depth;
  CmdTab	menu, cmd;
  char		*mark, *mark_save;
  const char	*errfmt;
  char		buf[100];
  int		err;

  for (mark = buf, depth = *buf = 0, menu = gCommands;
      depth < ac;
      depth++, menu = (CmdTab) cmd->arg) {
    if ((err = FindCommand(menu, av[depth], &cmd))) {
      int k;

      for (*buf = k = 0; k <= depth; k++)
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%c",
	  av[k], k == depth ? '\0' : ' ');
      switch (err) {
        case -1:
          errfmt = "%sUnknown command: '%s'. Try \"help\".";
	  break;
        case -2:
	  errfmt = "%sAmbiguous command: '%s'";
	  break;
	default:
	  errfmt = "%sUnknown error: '%s'";
      }
      if (arg) {
        Log(LG_ERR, (errfmt, (char*)arg, buf));
      } else {
        Log(LG_ERR, (errfmt, "", buf));
      }
      return(0);
    }
    sprintf(mark, depth ? " %s" : "%s", cmd->name);
    mark_save = mark;
    if ((mark = strchr(mark + 1, ' ')) == NULL)
      mark = mark_save + strlen(mark_save);
    if (cmd->func != CMD_SUBMENU)
    {
      Printf("Usage: %s\r\n", buf);
      return(0);
    }
  }

  /* Show list of available commands in this submenu */
  *mark = 0;
  if (!*buf)
    Printf("Available commands:\r\n");
  else
    Printf("Commands available under \"%s\":\r\n", buf);
  for (cmd = menu; cmd->name; cmd++) {
    snprintf(buf, sizeof(buf), "%s", cmd->name);
    if ((mark = strchr(buf, ' ')))
      *mark = 0;
    Printf(" %-9s: %-20s%s", buf, cmd->desc,
      ((cmd - menu) & 1)? "\r\n" : "\t");
  }
  if ((cmd - menu) & 1)
    Printf("\r\n");
  return(0);
}

/*
 * SetDebugCommand()
 */

static int
SetDebugCommand(Context ctx, int ac, char *av[], void *arg)
{
  switch (ac) {
    case 1:
      NgSetDebug(atoi(av[0]));
      break;
    default:
      return(-1);
  }
  return(0);
}

/*
 * ShowVersion()
 */

static int
ShowVersion(Context ctx, int ac, char *av[], void *arg)
{
  Printf("MPD version: %s\r\n", gVersion);
  Printf("  Compiled-in system features:\r\n");
#ifdef	USE_NG_CAR
  Printf("	ng_car		: yes\r\n");
#else
  Printf("	ng_car		: no\r\n");
#endif
#ifdef	USE_NG_DEFLATE
  Printf("	ng_deflate	: yes\r\n");
#else
  Printf("	ng_deflate	: no\r\n");
#endif
#ifdef	USE_NG_IPACCT
  Printf("	ng_ipacct	: yes\r\n");
#else
  Printf("	ng_ipacct	: no\r\n");
#endif
#ifdef	USE_NG_NAT
  Printf("	ng_nat		: yes\r\n");
#else
  Printf("	ng_nat		: no\r\n");
#endif
#ifdef	USE_NG_NETFLOW
  Printf("	ng_netflow	: yes\r\n");
#else
  Printf("	ng_netflow	: no\r\n");
#endif
#ifdef	USE_NG_PRED1
  Printf("	ng_pred1	: yes\r\n");
#else
  Printf("	ng_pred1	: emulated\r\n");
#endif
#ifdef	USE_NG_TCPMSS
  Printf("	ng_tcpmss	: yes\r\n");
#else
  Printf("	ng_tcpmss	: emulated\r\n");
#endif
  return(0);
}

/*
 * ShowEvents()
 */

static int
ShowEvents(Context ctx, int ac, char *av[], void *arg)
{
  EventDump(ctx, "mpd events");
  return(0);
}

/*
 * ShowGlobal()
 */

static int
ShowGlobal(Context ctx, int ac, char *av[], void *arg)
{
  Printf("Global settings:\r\n");
  Printf("	startrule	: %d\r\n", rule_pool_start);
  Printf("	startpipe	: %d\r\n", pipe_pool_start);
  Printf("	startqueue	: %d\r\n", queue_pool_start);
  Printf("	starttable	: %d\r\n", table_pool_start);
  Printf("Global options:\r\n");
  OptStat(ctx, &gGlobalConf.options, gGlobalConfList);
  return 0;
}


/*
 * ExitCommand()
 */

static int
ExitCommand(Context ctx, int ac, char *av[], void *arg)
{
  exitflag = TRUE;
  return(0);
}

/*
 * QuitCommand()
 */

static int
QuitCommand(Context ctx, int ac, char *av[], void *arg)
{
  SendSignal(SIGTERM);
  exitflag = TRUE;
  return(0);
}

/*
 * NullCommand()
 */

static int
NullCommand(Context ctx, int ac, char *av[], void *arg)
{
  return(0);
}

/*
 * LoadCommand()
 */

static int
LoadCommand(Context ctx, int ac, char *av[], void *arg)
{
  static int depth=0;
  
  if (ac != 1)
    return(-1);
  else {
    if (depth>20) {
      Log(LG_ERR, ("Depth limit was reached while loading '%s'!", *av));
      Log(LG_ERR, ("There is a configuration loop!"));
      return(-2);
    }
    depth++;
    ReadFile(gConfigFile, *av, DoCommand, ctx);
    depth--;
  }
  return(0);
}

/*
 * OpenCommand()
 */

static int
OpenCommand(Context ctx, int ac, char *av[], void *arg)
{
  Layer		layer;
  const char	*name;

  switch (ac) {
    case 0:
      name = DEFAULT_OPEN_LAYER;
      break;
    case 1:
      name = av[0];
      break;
    default:
      return(-1);
  }
  if ((layer = GetLayer(name)) != NULL)
    (*layer->opener)(ctx);
  return(0);
}

/*
 * CloseCommand()
 */

static int
CloseCommand(Context ctx, int ac, char *av[], void *arg)
{
  Layer		layer;
  const char	*name;

  switch (ac) {
    case 0:
      name = DEFAULT_OPEN_LAYER;
      break;
    case 1:
      name = av[0];
      break;
    default:
      return(-1);
  }
  if ((layer = GetLayer(name)) != NULL)
    (*layer->closer)(ctx);
  return(0);
}

/*
 * GetLayer()
 */

static Layer
GetLayer(const char *name)
{
  int	k, found;

  if (name == NULL)
    name = "iface";
  for (found = -1, k = 0; k < NUM_LAYERS; k++) {
    if (!strncasecmp(name, gLayers[k].name, strlen(name))) {
      if (found > 0) {
	Log(LG_ERR, ("%s: ambiguous", name));
	return(NULL);
      } else
	found = k;
    }
  }
  if (found < 0) {
    Log(LG_ERR, ("unknown layer \"%s\": try \"show layers\"", name));
    return(NULL);
  }
  return(&gLayers[found]);
}

/*
 * ShowLayers()
 */

static int
ShowLayers(Context ctx, int ac, char *av[], void *arg)
{
  int	k;

  Printf("\tName\t\tDescription\r\n"
	 "\t----\t\t-----------\r\n");
  for (k = 0; k < NUM_LAYERS; k++)
    Printf("\t%s\t\t%s\r\n", gLayers[k].name, gLayers[k].desc);
  return(0);
}

/*
 * ShowTypes()
 */

static int
ShowTypes(Context ctx, int ac, char *av[], void *arg)
{
  PhysType	pt;
  int		k;

  Printf("Supported device types:\r\n\t");
  for (k = 0; (pt = gPhysTypes[k]); k++)
    Printf(" %s", pt->name);
  Printf("\r\n");
  return(0);
}

/*
 * ShowSummary()
 */

static int
ShowSummary(Context ctx, int ac, char *av[], void *arg)
{
  int		b,l;
  Bund		B;
  Link  	L;
  Rep		R;
  PhysInfo 	P;
  char	buf[64];

  Printf("Current daemon status summary\r\n");
  Printf("Iface\t\tBund\tLink\tLCP\tDevice\t\tUser\t\tFrom\r\n");
  for (b = 0; b<gNumBundles; b++) {
    B=gBundles[b];
    if (B) {
	Printf("%s\t%s\t%s\t", B->iface.ifname, (B->iface.up?"Up":"Down"), B->name);
	for (l = 0; l < B->n_links; l++) {
	    if (l != 0) {
		Printf("\t\t\t");
	    }
	    L=B->links[l];
	    if (L) {
		PhysGetPeerAddr(L->phys, buf, sizeof(buf));
		Printf("%s\t%s\t%s\t%s\t%8s\t%s", 
		    L->name,
		    FsmStateName(L->lcp.fsm.state),
		    (L->phys->type?L->phys->type->name:""),
		    gPhysStateNames[L->phys->state],
		    L->lcp.auth.params.authname,
		    buf
		    );
		Printf("\r\n");
	    }
	}
    }
  }
  for (b = 0; b<gNumReps; b++) {
    R=gReps[b];
    if (R) {
	Printf("Repeater\t%s\t", R->name);
	for (l = 0; l < 2; l++) {
	    if (l != 0) {
		Printf("\t\t\t");
	    }
	    P=R->physes[l];
	    if (P) {
		PhysGetPeerAddr(P, buf, sizeof(buf));
		Printf("%s\t%s\t%s\t%s\t%8s\t%s", 
		    P->name,
		    "",
		    (P->type?P->type->name:""),
		    gPhysStateNames[P->state],
		    "",
		    buf
		    );
		Printf("\r\n");
	    }
	}
    }
  }
  return(0);
}

/*
 * AdmitBund()
 */

int
AdmitBund(Context ctx, CmdTab cmd)
{
  if (!ctx->bund) {
    Log(LG_ERR, ("No bundle selected for '%s' command", cmd->name));
    return(FALSE);
  }
  return(TRUE);
}

/*
 * AdmitLink()
 */

int
AdmitLink(Context ctx, CmdTab cmd)
{
  if (!ctx->lnk) {
    Log(LG_ERR, ("No link selected for '%s' command", cmd->name));
    return(FALSE);
  }
  return(TRUE);
}

/*
 * AdmitRep()
 */

int
AdmitRep(Context ctx, CmdTab cmd)
{
  if (!ctx->rep) {
    Log(LG_ERR, ("No repeater selected for '%s' command", cmd->name));
    return(FALSE);
  }
  return(TRUE);
}

/*
 * AdmitPhys()
 */

int
AdmitPhys(Context ctx, CmdTab cmd)
{
  if (!ctx->phys) {
    Log(LG_ERR, ("No phys selected for '%s' command", cmd->name));
    return(FALSE);
  }
  return(TRUE);
}

/*
 * AdmitDev()
 */

int
AdmitDev(Context ctx, CmdTab cmd)
{
  if (!ctx->phys) {
    Log(LG_ERR, ("No phys selected for '%s' command", cmd->name));
    return(FALSE);
  }
  if (ctx->phys->type == NULL) {
    Log(LG_ERR, ("Type of phys \"%s\" is unspecified for '%s' command", ctx->phys->name, cmd->name));
    return(FALSE);
  }
  if (strncmp(cmd->name, ctx->phys->type->name, strlen(ctx->phys->type->name))) {
    Log(LG_ERR, ("[%s] Phys type is %s, '%s' command isn't allowed here!",
      ctx->phys->name, ctx->phys->type->name, cmd->name));
    return(FALSE);
  }
  return(TRUE);
}

