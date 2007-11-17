/*
 * See ``COPYRIGHT.mpd''
 *
 * $Id: event.h,v 1.7 2007/11/14 20:52:05 amotin Exp $
 *
 */

#ifndef _EVENT_H_
#define _EVENT_H_

/*
 * DEFINITIONS
 */

/* Types of events */

  #define EVENT_READ		PEVENT_READ	/* value = file descriptor */
  #define EVENT_WRITE		PEVENT_WRITE	/* value = file descriptor */
  #define EVENT_TIMEOUT		PEVENT_TIME	/* value = time in miliseconds */
  
  #define EVENT_RECURRING	PEVENT_RECURRING

  typedef void		(*EventHdlr)(int type, void *cookie);

  struct event_ref
  {
    int			type;
    EventHdlr		handler;
    struct pevent	*pe;
    void		*arg;
    const char		*dbg;
  };
  typedef struct event_ref	EventRef;

/*
 * FUNCTIONS
 */

  extern int	EventInit(void);
  extern void	EventStop(void);
#define EventRegister(ref, type, value, flags, action, cookie) 		\
	    EventRegister2(ref, type, value, flags, action, cookie,	\
	    #type " " #action "()",__FILE__, __LINE__)
  extern int	EventRegister2(EventRef *ref, int type, int value,
		  int flags, EventHdlr action, void *cookie, const char *dbg,
		  const char *file, int line);
#define EventUnRegister(ref)						\
	    EventUnRegister2(ref, __FILE__, __LINE__)
  extern int	EventUnRegister2(EventRef *ref, const char *file, int line);
  extern int	EventIsRegistered(EventRef *ref);
  extern int	EventTimerRemain(EventRef *ref);
  extern void	EventDump(Context ctx, const char *msg);

  extern void	EventSetLog(int sanity, void (*warnx)(const char *fmt, ...));

#endif

