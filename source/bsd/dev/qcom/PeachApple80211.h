/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PEACH_APPLE80211_H
#define PEACH_APPLE80211_H
#include <sys/types.h>
enum { PeachAppleScanDone = 10, PeachAppleJoinDone = 9 };
int peach_apple80211_ioctl(u_long, void *);
void peach_apple80211_event(unsigned);
void peach_apple80211_link(unsigned status, int rssi); /* 0 manual down, 1 up, 2 lost */
#endif
