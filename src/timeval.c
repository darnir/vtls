/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <time.h>
#include <stdbool.h>
#include "timeval.h"

#if defined(WIN32) && !defined(MSDOS)

struct timeval curlx_tvnow(void)
{
	/*
	 ** GetTickCount() is available on _all_ Windows versions from W95 up
	 ** to nowadays. Returns milliseconds elapsed since last system boot,
	 ** increases monotonically and wraps once 49.7 days have elapsed.
	 */
	struct timeval now;
	DWORD milliseconds = GetTickCount();
	now.tv_sec = milliseconds / 1000;
	now.tv_usec = (milliseconds % 1000) * 1000;
	return now;
}

#elif defined(HAVE_CLOCK_GETTIME)

struct timeval curlx_tvnow(void)
{
	/*
	 ** clock_gettime() is granted to be increased monotonically when the
	 ** monotonic clock is queried. Time starting point is unspecified, it
	 ** could be the system start-up time, the Epoch, or something else,
	 ** in any case the time starting point does not change once that the
	 ** system has started up.
	 */
	struct timeval now;
	struct timespec tsnow;
	if (0 == clock_gettime(CLOCK_MONOTONIC, &tsnow)) {
		now.tv_sec = tsnow.tv_sec;
		now.tv_usec = tsnow.tv_nsec / 1000;
	}		/*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** run-time. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
	else
		(void) gettimeofday(&now, NULL);
#else
	else {
		now.tv_sec = (long) time(NULL);
		now.tv_usec = 0;
	}
#endif
	return now;
}

#elif defined(HAVE_GETTIMEOFDAY)

struct timeval curlx_tvnow(void)
{
	/*
	 ** gettimeofday() is not granted to be increased monotonically, due to
	 ** clock drifting and external source time synchronization it can jump
	 ** forward or backward in time.
	 */
	struct timeval now;
	(void) gettimeofday(&now, NULL);
	return now;
}

#else

struct timeval curlx_tvnow(void)
{
	/*
	 ** time() returns the value of time in seconds since the Epoch.
	 */
	struct timeval now;
	now.tv_sec = (long) time(NULL);
	now.tv_usec = 0;
	return now;
}

#endif

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we'll get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
long curlx_tvdiff(struct timeval newer, struct timeval older)
{
	return (newer.tv_sec - older.tv_sec)*1000 +
		(newer.tv_usec - older.tv_usec) / 1000;
}

/*
 * Same as curlx_tvdiff but with full usec resolution.
 *
 * Returns: the time difference in seconds with subsecond resolution.
 */
double curlx_tvdiff_secs(struct timeval newer, struct timeval older)
{
	if (newer.tv_sec != older.tv_sec)
		return (double) (newer.tv_sec - older.tv_sec) +
		(double) (newer.tv_usec - older.tv_usec) / 1000000.0;
	else
		return (double) (newer.tv_usec - older.tv_usec) / 1000000.0;
}

/*
 * Curl_timeleft() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is negative, the timeout time has already
 * elapsed.
 *
 * The start time is stored in progress.t_startsingle - as set with
 * Curl_pgrsTime(..., TIMER_STARTSINGLE);
 *
 * If 'nowp' is non-NULL, it points to the current time.
 * 'duringconnect' is FALSE if not during a connect, as then of course the
 * connect timeout is not taken into account!
 *
 * @unittest: 1303
 */
long Curl_timeleft(struct SessionHandle *data,
                   struct timeval *nowp,
                   bool duringconnect)
{
  int timeout_set = 0;
  long timeout_ms = duringconnect?DEFAULT_CONNECT_TIMEOUT:0;
  struct timeval now;

  /* if a timeout is set, use the most restrictive one */

  if(data->set.timeout > 0)
    timeout_set |= 1;
  if(duringconnect && (data->set.connecttimeout > 0))
    timeout_set |= 2;

  switch (timeout_set) {
  case 1:
    timeout_ms = data->set.timeout;
    break;
  case 2:
    timeout_ms = data->set.connecttimeout;
    break;
  case 3:
    if(data->set.timeout < data->set.connecttimeout)
      timeout_ms = data->set.timeout;
    else
      timeout_ms = data->set.connecttimeout;
    break;
  default:
    /* use the default */
    if(!duringconnect)
      /* if we're not during connect, there's no default timeout so if we're
         at zero we better just return zero and not make it a negative number
         by the math below */
      return 0;
    break;
  }

  if(!nowp) {
    now = Curl_tvnow();
    nowp = &now;
  }

  /* subtract elapsed time */
  if(duringconnect)
    /* since this most recent connect started */
    timeout_ms -= Curl_tvdiff(*nowp, data->progress.t_startsingle);
  else
    /* since the entire operation started */
    timeout_ms -= Curl_tvdiff(*nowp, data->progress.t_startop);
  if(!timeout_ms)
    /* avoid returning 0 as that means no timeout! */
    return -1;

  return timeout_ms;
}

/* return the number of seconds in the given input timeval struct */
long Curl_tvlong(struct timeval t1)
{
	return t1.tv_sec;
}
