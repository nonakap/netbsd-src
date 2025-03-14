/*
 * Generated by dtrace(1M).
 */

#ifndef	_PROBES_H
#define	_PROBES_H

#include <unistd.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sdt.h>

#if defined(DTRACE) && _DTRACE_VERSION

#define	LIBNS_RRL_DROP(arg0, arg1, arg2, arg3) \
	__dtrace_libns___rrl_drop(arg0, arg1, arg2, arg3)
#ifndef	__sparc
#define	LIBNS_RRL_DROP_ENABLED() \
	__dtraceenabled_libns___rrl_drop()
#else
#define	LIBNS_RRL_DROP_ENABLED() \
	__dtraceenabled_libns___rrl_drop(0)
#endif


extern void __dtrace_libns___rrl_drop(char *, char *, char *, int);
#ifndef	__sparc
extern int __dtraceenabled_libns___rrl_drop(void);
#else
extern int __dtraceenabled_libns___rrl_drop(long);
#endif

#else

#define	LIBNS_RRL_DROP(arg0, arg1, arg2, arg3)
#define	LIBNS_RRL_DROP_ENABLED() (0)

#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _PROBES_H */
