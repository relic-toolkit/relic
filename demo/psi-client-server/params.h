/* Set sizes, which can be overridden at compile time with -DM=... -DN=... */
#ifndef M
#define M	(1 << 8)	/* Receiver (server). */
#endif
#ifndef N
#define N	(1 << 8)	/* Sender (client). */
#endif

#define SK "258B8F5E39671B337C1E3B87559B579D3F878E5293DF2B01DE1B9E10CA9EC9D0"
