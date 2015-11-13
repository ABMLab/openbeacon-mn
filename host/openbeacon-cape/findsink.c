/*
//=========================================================================
//
// File:    findsink.c
// Created: 10-27-2015, 10:12 AM
//
// Author : Mehdi Najafi
//
// Data Sink Scanner and Finder (Client Side) for BeagleBone Readers
// Copyright (C) 2015 ABMLAB @ York University
// Not premitted to be distributed and/or modified under any conditions.
//=========================================================================
*/

#define PACKAGE_STRING "find_data_sink"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <regex.h>		/* Posix regular expression functions */
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include<pthread.h>

/*//namespace findsink
//{
*/

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAX_FRAME 2048			/* Maximum allowed frame size */
#define REALLOC_COUNT 1000		/* Entries to realloc at once */
#define DEFAULT_BANDWIDTH 256000	/* Default bandwidth in bits/sec */
#define PACKET_OVERHEAD 18		/* layer 2 overhead (6+6+2 + 4) */
#define MINIMUM_FRAME_SIZE 46           /* Minimum layer 2 date size */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 2                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */
#define SNAPLEN 64			/* 14 (ether) + 28 (ARP) + extra */
#define PROMISC 0			/* Enable promiscuous mode */
#define TO_MS 0				/* Timeout for pcap_open_live() */
#define OPTIMISE 1			/* Optimise pcap filter */
#define ARPHRD_ETHER 1			/* Ethernet ARP type */
#define ARPOP_REQUEST 1			/* ARP Request */
#define ARPOP_REPLY 2			/* ARP Reply */
#define ETHER_HDR_SIZE 14		/* Size of Ethernet frame header in bytes */
#define ARP_PKT_SIZE 28			/* Size of ARP Packet in bytes */
#define ETH_ALEN 6			/* Octets in one ethernet addr */
#define ETH_P_IP 0x0800			/* Internet Protocol packet */
#define ETH_P_ARP 0x0806		/* Address Resolution packet */
#define DEFAULT_ARP_OP ARPOP_REQUEST	/* Default ARP operation */
#define DEFAULT_ARP_HRD ARPHRD_ETHER	/* Default ARP hardware type */
#define DEFAULT_ARP_PRO ETH_P_IP	/* Default ARP protocol */
#define DEFAULT_ARP_HLN 6		/* Default hardware length */
#define DEFAULT_ARP_PLN 4		/* Default protocol length */
#define DEFAULT_ETH_PRO	ETH_P_ARP	/* Default Ethernet protocol */
#define FRAMING_ETHERNET_II 0		/* Standard Ethernet-II Framing */
#define FRAMING_LLC_SNAP 1		/* 802.3 with LLC/SNAP */
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#define OPT_WRITEPKTTOFILE 256		/* --writepkttofile option */
#define OPT_READPKTFROMFILE 257		/* --readpktfromfile option */
#define OPT_RANDOMSEED 258		/* --randomseed option */

/* Structures */

typedef struct {
   unsigned timeout;		/* Timeout for this host in us */
   struct in_addr addr;		/* Host IP address */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned short num_sent;	/* Number of packets sent */
   unsigned short num_recv;	/* Number of packets received */
   unsigned char live;		/* Set when awaiting response */
} host_entry;

/* Ethernet frame header */
typedef struct {
   uint8_t dest_addr[ETH_ALEN];	/* Destination hardware address */
   uint8_t src_addr[ETH_ALEN];	/* Source hardware address */
   uint16_t frame_type;		/* Ethernet frame type */
} ether_hdr;

/* Ethernet ARP packet from RFC 826 */
typedef struct {
   uint16_t ar_hrd;		/* Format of hardware address */
   uint16_t ar_pro;		/* Format of protocol address */
   uint8_t ar_hln;		/* Length of hardware address */
   uint8_t ar_pln;		/* Length of protocol address */
   uint16_t ar_op;		/* ARP opcode (command) */
   uint8_t ar_sha[ETH_ALEN];	/* Sender hardware address */
   uint32_t ar_sip;		/* Sender IP address */
   uint8_t ar_tha[ETH_ALEN];	/* Target hardware address */
   uint32_t ar_tip;		/* Target IP address */
} arp_ether_ipv4;


/* possible data sinks ip addresses*/
struct ulongnode {
  uint32_t addr;
  struct ulongnode *prev;
};
struct stringnode {
  char *str;
  struct stringnode *prev;
};
/* This will be the unchanging first node */
struct stringnode *g_sinklist = NULL;
struct ulongnode *g_sinklistaddr = NULL;


#define SAFE_FREE(a) {if(a!=NULL){free((void*)a);a=NULL;}}



/* Functions */

#ifndef HAVE_STRLCAT
/*
 * '_cups_strlcat()' - Safely concatenate two strings.
 */

size_t                  /* O - Length of string */
strlcat(char       *dst,        /* O - Destination string */
              const char *src,      /* I - Source string */
          size_t     size)      /* I - Size of destination string buffer */
{
  size_t    srclen;         /* Length of source string */
  size_t    dstlen;         /* Length of destination string */


 /*
  * Figure out how much room is left...
  */

  dstlen = strlen(dst);
  size   -= dstlen + 1;

  if (!size)
    return (dstlen);        /* No room, return immediately... */

 /*
  * Figure out how much room is needed...
  */

  srclen = strlen(src);

 /*
  * Copy the appropriate amount...
  */

  if (srclen > size)
    srclen = size;

  memcpy(dst + dstlen, src, srclen);
  dst[dstlen + srclen] = '\0';

  return (dstlen + srclen);
}
#endif /* !HAVE_STRLCAT */

#ifndef HAVE_STRLCPY
/*
 * '_cups_strlcpy()' - Safely copy two strings.
 */

size_t                  /* O - Length of string */
strlcpy(char       *dst,        /* O - Destination string */
              const char *src,      /* I - Source string */
          size_t      size)     /* I - Size of destination string buffer */
{
  size_t    srclen;         /* Length of source string */


 /*
  * Figure out how much room is needed...
  */

  size --;

  srclen = strlen(src);

 /*
  * Copy the appropriate amount...
  */

  if (srclen > size)
    srclen = size;

  memcpy(dst, src, srclen);
  dst[srclen] = '\0';

  return (srclen);
}
#endif /* !HAVE_STRLCPY */
/*
 * utility functions
 */


/* Error*/

int daemon_proc;	/* Non-zero if process is a daemon */

/*
 *	General error printing function used by all the above
 *	functions.
 */
void
err_print (int errnoflag, const char *fmt, va_list ap) {
   int errno_save;
   size_t n;
   char buf[MAXLINE];

   errno_save=errno;

   vsnprintf(buf, MAXLINE, fmt, ap);
   n=strlen(buf);
   if (errnoflag)
     snprintf(buf+n, MAXLINE-n, ": %s", strerror(errno_save));
   strlcat(buf, "\n", MAXLINE); // sizeof(buf)

   printf("%s", buf);

   fflush(stdout);	/* In case stdout and stderr are the same */
   fputs(buf, stderr);
   fflush(stderr);
}

/*
 *	Function to handle fatal system call errors.
 */
void
err_sys(const char *fmt,...) {
   va_list ap;
   va_start(ap, fmt);
   err_print(1, fmt, ap);
   va_end(ap);
   /*exit(EXIT_FAILURE);*/
}

/*
 *	Function to handle non-fatal system call errors.
 */
void
warn_sys(const char *fmt,...) {
   va_list ap;
   va_start(ap, fmt);
   err_print(1, fmt, ap);
   va_end(ap);
}

/*
 *	Function to handle fatal errors not from system calls.
 */
void
err_msg(const char *fmt,...) {
   va_list ap;
   va_start(ap, fmt);
   err_print(0, fmt, ap);
   va_end(ap);
   /*exit(EXIT_FAILURE);*/
}

/*
 *	Function to handle non-fatal errors not from system calls.
 */
void
warn_msg(const char *fmt,...) {
   va_list ap;
   va_start(ap, fmt);
   err_print(0, fmt, ap);
   va_end(ap);
}



/*
 * We omit the timezone arg from this wrapper since it's obsolete and we never
 * use it.
 */
int Gettimeofday(struct timeval *tv) {
   int result;

   result = gettimeofday(tv, NULL);

   if (result != 0)
      err_sys("gettimeofday");

   return result;
}

void *Malloc(size_t size) {
   void *result;

   result = malloc(size);

   if (result == NULL)
      err_sys("malloc");

   return result;
}

void *Realloc(void *ptr, size_t size) {
   void *result;

   result=realloc(ptr, size);

   if (result == NULL)
      err_sys("realloc");

   return result;
}

/*
 *	dupstr -- duplicate a string
 *
 *	Inputs:
 *
 *	str	The string to duplcate
 *
 *	Returns:
 *
 *	A pointer to the duplicate string.
 *
 *	This is a replacement for the common but non-standard "strdup"
 *	function.
 *
 *	The returned pointer points to Malloc'ed memory, which must be
 *	free'ed by the caller.
 */
char *
dupstr(const char *str) {
   char *cp;
   size_t len;

   len = strlen(str) + 1;	/* Allow space for terminating NULL */
   cp = (char*)Malloc(len);
   strlcpy(cp, str, len);
   return cp;
}

unsigned long int Strtoul(const char *nptr, int base) {
   char *endptr;
   unsigned long int result;

   result=strtoul(nptr, &endptr, base);
   if (endptr == nptr)	/* No digits converted */
      err_msg("ERROR: \"%s\" is not a valid numeric value", nptr);
   if (*endptr != '\0' && !isspace((unsigned char)*endptr))
      err_msg("ERROR: \"%s\" is not a valid numeric value", nptr);

   return result;
}

long int Strtol(const char *nptr, int base) {
   char *endptr;
   long int result;

   result=strtol(nptr, &endptr, base);
   if (endptr == nptr)	/* No digits converted */
      err_msg("ERROR: \"%s\" is not a valid numeric value", nptr);
   if (*endptr != '\0' && !isspace((unsigned char)*endptr))
      err_msg("ERROR: \"%s\" is not a valid numeric value", nptr);

   return result;
}

/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a       = First timeval
 *	b       = Second timeval
 *	diff    = Difference between timevals (a - b).
 *
 *	Returns:
 *
 *	None.
 */
void
timeval_diff(const struct timeval *a, const struct timeval *b,
             struct timeval *diff) {
   struct timeval temp;

   temp.tv_sec = b->tv_sec;
   temp.tv_usec = b->tv_usec;

   /* Perform the carry for the later subtraction by updating b. */
   if (a->tv_usec < temp.tv_usec) {
     int nsec = (temp.tv_usec - a->tv_usec) / 1000000 + 1;
     temp.tv_usec -= 1000000 * nsec;
     temp.tv_sec += nsec;
   }
   if (a->tv_usec - temp.tv_usec > 1000000) {
     int nsec = (a->tv_usec - temp.tv_usec) / 1000000;
     temp.tv_usec += 1000000 * nsec;
     temp.tv_sec -= nsec;
   }

   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - temp.tv_sec;
   diff->tv_usec = a->tv_usec - temp.tv_usec;
}

/*
 *	hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *	Inputs:
 *
 *	cptr	Two-digit hex string
 *
 *	Returns:
 *
 *	Number corresponding to input hex value.
 *
 *	An input of "0A" or "0a" would return 10.
 *	Note that this function does no sanity checking, it's up to the
 *	caller to ensure that *cptr points to at least two hex digits.
 *
 *	This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int
hstr_i(const char *cptr)
{
      unsigned int i;
      unsigned int j = 0;
      int k;

      for (k=0; k<2; k++) {
            i = *cptr++ - '0';
            if (9 < i)
                  i -= 7;
            j <<= 4;
            j |= (i & 0x0f);
      }
      return j;
}

/*
 * make_message -- allocate a sufficiently large string and print into it.
 *
 * Inputs:
 *
 * Format and variable number of arguments.
 *
 * Outputs:
 *
 * Pointer to the string,
 *
 * The code for this function is from the Debian Linux "woody" sprintf man
 * page.  Modified slightly to use wrapper functions for malloc and realloc.
 */

char * make_message(const char *fmt, ...) {
   int n;
   /* Guess we need no more than 100 bytes. */
   size_t size = 100;
   char *p;
   va_list ap;
   p = (char*)Malloc (size);
   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (p, size, fmt, ap);
      va_end(ap);
      /* If that worked, return the string. */
      if (n > -1 && n < (int) size)
	      return p;
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      p = (char*)Realloc (p, size);
   }
}

/*
 *	hexstring -- Convert data to printable hex string form
 *
 *	Inputs:
 *
 *	string	Pointer to input data.
 *	size	Size of input data.
 *
 *	Returns:
 *
 *	Pointer to the printable hex string.
 *
 *	Each byte in the input data will be represented by two hex digits
 *	in the output string.  Therefore the output string will be twice
 *	as long as the input data plus one extra byte for the trailing NULL.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *
hexstring(const unsigned char *data, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   unsigned i;
/*
 *	If the input data is NULL, return an empty string.
 */
   if (data == NULL) {
      result = (char*)Malloc(1);
      result[0] = '\0';
      return result;
   }
/*
 *	Create and return hex string.
 */
   result = (char*)Malloc(2*size + 1);
   cp = data;
   r = result;
   for (i=0; i<size; i++) {
      snprintf(r, 3, "%.2x", *cp++);
      r += 2;
   }
   *r = '\0';

   return result;
}

/*
 * get_ether_addr -- Get Ethernet hardware address from text string
 *
 * Inputs:
 *
 * address_string	The text string containing the address
 * ether_addr		(output) The Ethernet hardware address
 *
 * Returns:
 *
 * Zero on success or -1 on failure.
 *
 * The address_string should contain an Ethernet hardware address in one
 * of the following formats:
 *
 * 01-23-45-67-89-ab
 * 01:23:45:67:89:ab
 *
 * The hex characters [a-z] may be specified in either upper or lower case.
 */
int
get_ether_addr(const char *address_string, unsigned char *ether_addr) {
   unsigned mac_b0, mac_b1, mac_b2, mac_b3, mac_b4, mac_b5;
   int result;

   result = sscanf(address_string, "%x:%x:%x:%x:%x:%x",
                   &mac_b0, &mac_b1, &mac_b2, &mac_b3, &mac_b4, &mac_b5);
   if (result !=6 ) {
      result = sscanf(address_string, "%x-%x-%x-%x-%x-%x",
                      &mac_b0, &mac_b1, &mac_b2, &mac_b3, &mac_b4, &mac_b5);
   }
   if (result !=6 ) {
      return -1;
   }
   ether_addr[0] = mac_b0;
   ether_addr[1] = mac_b1;
   ether_addr[2] = mac_b2;
   ether_addr[3] = mac_b3;
   ether_addr[4] = mac_b4;
   ether_addr[5] = mac_b5;

   return 0;
}

/*
 *	str_to_bandwidth -- Convert a bandwidth string to unsigned integer
 *
 *	Inputs:
 *
 *	bandwidth_string	The bandwidth string to convert
 *
 *	Returns:
 *
 *	The bandwidth in bits per second as an unsigned integer
 */
unsigned
str_to_bandwidth(const char *bandwidth_string) {
   char *bandwidth_str;
   size_t bandwidth_len;
   unsigned value;
   int multiplier=1;
   int end_char;

   bandwidth_str=dupstr(bandwidth_string);	/* Writable copy */
   bandwidth_len=strlen(bandwidth_str);
   end_char = bandwidth_str[bandwidth_len-1];
   if (!isdigit(end_char)) {	/* End character is not a digit */
      bandwidth_str[bandwidth_len-1] = '\0';	/* Remove last character */
      switch (end_char) {
         case 'M':
         case 'm':
            multiplier = 1000000;
            break;
         case 'K':
         case 'k':
            multiplier = 1000;
            break;
         default:
            err_msg("ERROR: Unknown bandwidth multiplier character: \"%c\"",
                    end_char);
            break;
      }
   }
   value=Strtoul(bandwidth_str, 10);
   free(bandwidth_str);
   return multiplier * value;
}

/*
 *	str_to_interval -- Convert an interval string to unsigned integer
 *
 *	Inputs:
 *
 *	interval_string		The interval string to convert
 *
 *	Returns:
 *
 *	The interval in microsecons as an unsigned integer
 */
unsigned
str_to_interval(const char *interval_string) {
   char *interval_str;
   size_t interval_len;
   unsigned value;
   int multiplier=1000;
   int end_char;

   interval_str=dupstr(interval_string);	/* Writable copy */
   interval_len=strlen(interval_str);
   end_char = interval_str[interval_len-1];
   if (!isdigit(end_char)) {	/* End character is not a digit */
      interval_str[interval_len-1] = '\0';	/* Remove last character */
      switch (end_char) {
         case 'U':
         case 'u':
            multiplier = 1;
            break;
         case 'S':
         case 's':
            multiplier = 1000000;
            break;
         default:
            err_msg("ERROR: Unknown interval multiplier character: \"%c\"",
                    end_char);
            break;
      }
   }
   value=Strtoul(interval_str, 10);
   free(interval_str);
   return multiplier * value;
}

void
get_hardware_address(const char *if_nam, unsigned char hw_address[]) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , if_nam , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	memcpy(hw_address, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

void
print_hardware_address_ip(const char *if_nam, unsigned char hw_address[]) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , if_nam , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	memcpy(hw_address, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	unsigned char mac[6];
	memcpy(mac,ifr.ifr_hwaddr.sa_data,6*sizeof(unsigned char));
//static  int is_first_time = 1;
//extern uint32_t g_reader_ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	/*Type of address to retrieve - IPv4 IP address*/
	ifr.ifr_addr.sa_family = AF_INET;
	/*Copy the interface name in the ifreq structure*/
	strncpy(ifr.ifr_name , if_nam , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	/*display result*/
	/*display mac & ip address if anything changed.*/
//	if(is_first_time==1 || g_reader_ip!=((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr)
    {
//        is_first_time = 0;
        printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x / %s:%s\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], if_nam,
            inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
    }

}

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void err_print(int, const char *, va_list);
void usage(int, int);
void add_host_pattern(const char *, unsigned);
void add_host(const char *, unsigned, int);
int send_packet(pcap_t *, host_entry *, struct timeval *);
void recvfrom_wto(int, int, pcap_t *);
void remove_host(host_entry **);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);
host_entry *find_host(host_entry **, struct in_addr *);
void *checkdatasink(void *data);
int display_packet(host_entry *, arp_ether_ipv4 *, const unsigned char *,
                    size_t, int, int, ether_hdr *, const struct pcap_pkthdr *);
void advance_cursor(void);
void dump_list(void);
void clean_up(pcap_t *);
void arp_scan_version(void);
char* make_message(const char *, ...);
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
struct in_addr *get_host_address(const char *, int, struct in_addr *, char **);
const char *my_ntoa(struct in_addr);
int get_source_ip(const char *, uint32_t *);
void get_hardware_address(const char *, unsigned char []);
void marshal_arp_pkt(unsigned char *, ether_hdr *, arp_ether_ipv4 *, size_t *,
                     const unsigned char *, size_t);
int unmarshal_arp_pkt(const unsigned char *, size_t, ether_hdr *,
                      arp_ether_ipv4 *, unsigned char *, size_t *, int *);
unsigned char *hex2data(const char *, size_t *);
unsigned int hstr_i(const char *);
char *hexstring(const unsigned char *, size_t);
int get_ether_addr(const char *, unsigned char *);
/* Wrappers */
int Gettimeofday(struct timeval *);
unsigned long int Strtoul(const char *, int);
long int Strtol(const char *, int);
unsigned str_to_bandwidth(const char *);
unsigned str_to_interval(const char *);
char *dupstr(const char *);
/* MT19937 prototypes */
void init_genrand(unsigned long);
void init_by_array(unsigned long[], int);
unsigned long genrand_int32(void);
long genrand_int31(void);
double genrand_real1(void);
double genrand_real2(void);
double genrand_real3(void);
double genrand_res53(void);




/* ----------------------------------------------------------------- */





/* Global variables */
static host_entry *helist = NULL;	/* Array of host entries */
static host_entry **helistptr = NULL;		/* Array of pointers to host entries */
static host_entry **cursor;		/* Pointer to current host entry ptr */
static unsigned num_hosts = 0;		/* Number of entries in the list */
static int num_left=0;	/* Number of free entries left */
static unsigned responders = 0;		/* Number of hosts which responded */
static unsigned live_count;		/* Number of entries awaiting reply */
static int verbose=0;			/* Verbose level */
static int numeric_flag=0;		/* IP addresses only */
static unsigned interval=0;		/* Desired interval between packets */
static unsigned bandwidth=DEFAULT_BANDWIDTH; /* Bandwidth in bits per sec */
static unsigned retry = DEFAULT_RETRY;	/* Number of retries */
static unsigned timeout = DEFAULT_TIMEOUT; /* Per-host timeout */
static float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
static int snaplen = SNAPLEN;		/* Pcap snap length */
static char *if_name=NULL;		/* Interface name, e.g. "eth0" */
static int quiet_flag=1;		/* Don't decode the packet */
static int ignore_dups=0;		/* Don't display duplicate packets */
static uint32_t arp_spa;		/* Source IP address */
static int arp_spa_flag=0;		/* Source IP address specified */
static int arp_spa_is_tpa=0;		/* Source IP is dest IP */
static unsigned char arp_sha[ETH_ALEN];	/* Source Ethernet MAC Address */
static int arp_sha_flag=0;		/* Source MAC address specified */
static char pcap_savefile[MAXLINE];	/* pcap savefile filename */
static int arp_op=DEFAULT_ARP_OP;	/* ARP Operation code */
static int arp_hrd=DEFAULT_ARP_HRD;	/* ARP hardware type */
static int arp_pro=DEFAULT_ARP_PRO;	/* ARP protocol */
static int arp_hln=DEFAULT_ARP_HLN;	/* Hardware address length */
static int arp_pln=DEFAULT_ARP_PLN;	/* Protocol address length */
static int eth_pro=DEFAULT_ETH_PRO;	/* Ethernet protocol type */
static unsigned char arp_tha[6] = {0, 0, 0, 0, 0, 0};
static unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static unsigned char source_mac[6];
static int source_mac_flag = 0;
static unsigned char *padding=NULL;
static size_t padding_len=0;
static int localnet_flag=0;		/* Scan local network */
static int llc_flag=0;			/* Use 802.2 LLC with SNAP */
static int ieee_8021q_vlan=-1;		/* Use 802.1Q VLAN tagging if >= 0 */
static int rtt_flag=0;			/* Display round-trip time */
static pcap_dumper_t *pcap_dump_handle = NULL;	/* pcap savefile handle */
static int plain_flag=0;		/* Only show host information */
unsigned int random_seed=0;
static pcap_t *pcap_handle = 0;		/* pcap handle */


typedef uint64_t  ARP_UINT64;
typedef int64_t  ARP_INT64;

void reset()
{
    struct stringnode *it;
    struct ulongnode *itl;
    while((it=g_sinklist)!=NULL)
    {
        free(it->str);
        g_sinklist = it->prev;
        free(it);
    }
    g_sinklist = NULL;
   while((itl=g_sinklistaddr)!=NULL)
    {
        g_sinklistaddr = itl->prev;
        free(itl);
    }
    g_sinklistaddr = NULL;
	num_hosts = 0;
	num_left = 0;

   clean_up(pcap_handle);

//	SAFE_FREE(if_name);
	SAFE_FREE(helist);
	SAFE_FREE(helistptr);

    localnet_flag = 1;
}

void cleanup()
{
    struct stringnode *it;
    struct ulongnode *itl;
    while((it=g_sinklist)!=NULL)
    {
        free(it->str);
        g_sinklist = it->prev;
        free(it);
    }
    g_sinklist = NULL;
   while((itl=g_sinklistaddr)!=NULL)
    {
        g_sinklistaddr = itl->prev;
        free(itl);
    }
    g_sinklistaddr = NULL;

	num_hosts = 0;
	num_left = 0;

    clean_up(pcap_handle);

	//SAFE_FREE(if_name);
	SAFE_FREE(helist);
	SAFE_FREE(helistptr);
}

char* findsink(const char *interface_name)
{
   struct timeval now;
   struct timeval diff;         /* Difference between two timevals */
   int select_timeout;          /* Select timeout */
   ARP_UINT64 loop_timediff;    /* Time since last packet sent in us */
   ARP_UINT64 host_timediff; /* Time since last pkt sent to this host (us) */
   struct timeval last_packet_time;     /* Time last packet was sent */
   int req_interval;		/* Requested per-packet interval */
   int cum_err=0;               /* Cumulative timing error */
   struct timeval start_time;   /* Program start time */
   struct timeval end_time;     /* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;      /* Elapsed time in seconds */
   int reset_cum_err;
   int pass_no = 0;
   int first_timeout=1;
   unsigned i;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program filter;
   char *filter_string;
   bpf_u_int32 netmask;
   bpf_u_int32 localnet;
   int datalink;
   int get_addr_status = 0;
   int pcap_fd;			/* Pcap file descriptor */
   unsigned char interface_mac[ETH_ALEN];
   pcap_if_t *devList, *devi;
   char timebuf[256];
 /*
 *      Initialise file names to the empty string.
 */
   pcap_savefile[0] = '\0';
       memset(errbuf,0,PCAP_ERRBUF_SIZE);


	reset();
/*
 *      Process options.
 */

   localnet_flag = 1;
   if (interface_name!=NULL)
       if_name = make_message("%s", interface_name);


/*
 *      Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
/*
 *	Obtain network interface details unless we're reading
 *	from a pcap file or writing to a binary file.
 */
   {
/*
 *	Determine network interface to use. If the interface was specified
 *	with the --interface option then use that, otherwise use
 *	pcap_lookupdev() to pick a suitable interface.
 */
   if (if_name==NULL) {
		/* get the devices list */
		if (pcap_findalldevs(&devList, errbuf) == -1)
		{
			err_msg("pcap_lookupdev: %s", errbuf);
			return NULL;
		}

		/* scan the list for a suitable device to capture from */
		for (devi = devList; devi != NULL; devi = devi->next)
		{

		    pcap_addr_t *dev_addr; /*interface address that used by pcap_findalldevs()*/

		    /* check if the device captureble*/
			if (memcmp(devi->name,"wlan",4)==0 && (dev_addr = devi->addresses) != NULL)
/*		        if (dev_addr->addr && dev_addr->netmask)*/
			    {
/*			printf("Found a device %s on address %s with netmask %s\n", devi->name,
 				inet_ntoa(((struct sockaddr_in *)dev_addr->addr)->sin_addr.s_addr),
 				inet_ntoa(((struct sockaddr_in *)dev_addr->netmask)->sin_addr.s_addr));
*/
			if_name = make_message("%s",devi->name);
			break;
		    }
		}
		pcap_freealldevs(devList);

	if (if_name==NULL)
	{
		if_name = pcap_lookupdev(errbuf);
		if (if_name==NULL)
		{
			err_msg("pcap_lookupdev: %s", errbuf);
			return NULL;
		}
		else
            if_name = make_message("%s",if_name);
	}
   }


/*
 *	Obtain the MAC address for the selected interface, and use this
 *	as default for the source hardware addresses in the frame header
 *	and ARP packet if the user has not specified their values.
 *
 *	Die with an error if we can't get the MAC address, as this
 *	indicates that the interface doesn't have a MAC address, so is
 *	probably not a compatible interface type.
 */
    time_t mytime = time(NULL);
    sprintf(timebuf,"%s",ctime(&mytime));
    timebuf[strlen(timebuf)-1]='\0';
    printf("\n%s sever_srch: ", timebuf);
   print_hardware_address_ip(if_name, interface_mac);
      get_hardware_address(if_name, interface_mac);
      if (interface_mac[0]==0 && interface_mac[1]==0 &&
          interface_mac[2]==0 && interface_mac[3]==0 &&
          interface_mac[4]==0 && interface_mac[5]==0) {
         err_msg("ERROR: Could not obtain MAC address for interface %s",
                 if_name);
		  return NULL;
      }
      if (source_mac_flag == 0)
         memcpy(source_mac, interface_mac, ETH_ALEN);
      if (arp_sha_flag == 0)
         memcpy(arp_sha, interface_mac, ETH_ALEN);
/*
 *	If the user has not specified the ARP source address, obtain the
 *	interface IP address and use that as the default value.
 */
      if (arp_spa_flag == 0) {
         get_addr_status = get_source_ip(if_name, &arp_spa);
         if (get_addr_status == -1) {
            warn_msg("WARNING: Could not obtain IP address for interface %s. ",if_name);
/*                     "Using 0.0.0.0 for", if_name);
            warn_msg("the source address, which is probably not what you want.");
            warn_msg("Either configure %s with an IP address, or manually specify"
                     " the address", if_name);
            warn_msg("with the --arpspa option.");*/
            memset(&arp_spa, '\0', sizeof(uint32_t));
            return NULL;
         }
      }
   }

/*
 *	Open the network device for reading with pcap, or the pcap file if we
 *	have specified --readpktfromfile. If we are writing packets to a binary
 *	file, then set pcap_handle to NULL as we don't need to read packets in
 *	this case.
 */
	if (!(pcap_handle = pcap_open_live(if_name, snaplen, PROMISC, TO_MS, errbuf)))
	{
		err_msg("pcap_open_live: %s", errbuf);
		return NULL;
	}


/*
 *	get and display the datalink details
 */
   if (pcap_handle) {
      if ((datalink=pcap_datalink(pcap_handle)) < 0)
      {err_msg("pcap_datalink: %s", pcap_geterr(pcap_handle));
	      return NULL;}
      if (!plain_flag) {
         printf("Interface: %s, datalink type: %s (%s)\n",
                if_name,
                pcap_datalink_val_to_name(datalink),
                pcap_datalink_val_to_description(datalink));
      }
      if (datalink != DLT_EN10MB) {
         warn_msg("WARNING: Unsupported datalink type");
      }
   }

/*
 *	If we are reading from a network device, then get the associated file
 *	descriptor and configure it, determine the interface IP network and
 *	netmask, and install a pcap filter to receive only ARP responses.
 *	If we are reading from a pcap file, or writing to a binary file, just
 *	set the file descriptor to -1 to indicate that it is not associated
 *	with a network device.
 */

   {
      if ((pcap_fd=pcap_get_selectable_fd(pcap_handle)) < 0)
      {
         err_msg("pcap_fileno: %s", pcap_geterr(pcap_handle));
	      return NULL;
      }
     if ((pcap_setnonblock(pcap_handle, 1, errbuf)) < 0)
     {err_msg("pcap_setnonblock: %s", errbuf);return NULL;}
/*
 * For the BPF pcap implementation, set the BPF device into immediate mode,
 * otherwise it will buffer the responses.
 */
#ifdef ARP_PCAP_BPF
#ifdef BIOCIMMEDIATE
      {
         unsigned int one = 1;

         if (ioctl(pcap_fd, BIOCIMMEDIATE, &one) < 0)
		{
		err_sys("ioctl BIOCIMMEDIATE");
     return NULL;
		}
      }
#endif /* BIOCIMMEDIATE */
#endif /* ARP_PCAP_BPF */
/*
 * For the DLPI pcap implementation on Solaris, set the bufmod timeout to
 * zero. This has the side-effect of setting the chunk size to zero as
 * well, so bufmod will pass all incoming messages on immediately.
 */
#ifdef ARP_PCAP_DLPI
      {
         struct timeval time_zero = {0, 0};

         if (ioctl(pcap_fd, SBIOCSTIME, &time_zero) < 0)
            {err_sys("ioctl SBIOCSTIME"); return NULL;}
      }
#endif


      if (pcap_lookupnet(if_name, &localnet, &netmask, errbuf) < 0) {
         memset(&localnet, 0, sizeof(bpf_u_int32));
         memset(&netmask, 0, sizeof(bpf_u_int32));
         if (localnet_flag) {
            warn_msg("ERROR: Could not obtain interface IP address and netmask");
            err_msg("ERROR: pcap_lookupnet: %s", errbuf);
		 return NULL;
         }
      }
/*
 *	The filter string selects packets addressed to our interface address
 *	that are Ethernet-II ARP packets, 802.3 LLC/SNAP ARP packets,
 *	802.1Q tagged ARP packets or 802.1Q tagged 802.3 LLC/SNAP ARP packets.
 */
      filter_string=make_message("ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x and "
                                 "(arp or (ether[14:4]=0xaaaa0300 and "
                                 "ether[20:2]=0x0806) or (ether[12:2]=0x8100 "
                                 "and ether[16:2]=0x0806) or "
                                 "(ether[12:2]=0x8100 and "
                                 "ether[18:4]=0xaaaa0300 and "
                                 "ether[24:2]=0x0806))",
                                 interface_mac[0], interface_mac[1],
                                 interface_mac[2], interface_mac[3],
                                 interface_mac[4], interface_mac[5]);
      if (verbose > 1)
         warn_msg("DEBUG: pcap filter string: \"%s\"", filter_string);
      if ((pcap_compile(pcap_handle, &filter, filter_string, OPTIMISE,
           netmask)) < 0)
         {err_msg("pcap_compile: %s", pcap_geterr(pcap_handle));return NULL;}
      free(filter_string);
      if ((pcap_setfilter(pcap_handle, &filter)) < 0)
      {err_msg("pcap_setfilter: %s", pcap_geterr(pcap_handle));return NULL;}
   }


/*
 *      Drop SUID privileges.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
	   return NULL;
   }
/*
 *	Open pcap savefile is the --pcapsavefile (-W) option was specified
 */
   if (*pcap_savefile != '\0') {
      if (!(pcap_dump_handle=pcap_dump_open(pcap_handle, pcap_savefile))) {
         err_msg("pcap_dump_open: %s", pcap_geterr(pcap_handle));
	      return NULL;
      }
   }


/*
 *      Populate the list from the specified file if --file was specified, or
 *	from the interface address and mask if --localnet was specified, or
 *      otherwise from the remaining command line arguments.
 */
      if (localnet_flag) {	/* Populate list from i/f addr & mask */
      struct in_addr if_network;
      struct in_addr if_netmask;
      char *c_network;
      char *c_netmask;
      char localnet_descr[32];

      if_network.s_addr = localnet;
      if_netmask.s_addr = netmask;
      c_network = make_message("%s", my_ntoa(if_network));
      c_netmask = make_message("%s", my_ntoa(if_netmask));
      snprintf(localnet_descr, 32, "%s:%s", c_network, c_netmask);
      free(c_network);
      free(c_netmask);

      if (verbose) {
         warn_msg("Using %s for localnet", localnet_descr);
      }
      add_host_pattern(localnet_descr, timeout);
   }
/*
 *      Check that we have at least one entry in the list.
 */
   if (!num_hosts)
   {
      err_msg("ERROR: No hosts to process.");
	   return NULL;
   }


/*
 *      Create and initialise array of pointers to host entries.
 */
   helistptr = (host_entry**)Malloc(num_hosts * sizeof(host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];

/*
 *      Set current host pointer (cursor) to start of list, zero
 *      last packet sent time, and set last receive time to now.
 */
   live_count = num_hosts;
   cursor = helistptr;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
/*
 *      Calculate the required interval to achieve the required outgoing
 *      bandwidth unless the interval was manually specified with --interval.
 */

   if (!interval) {
      size_t packet_out_len;

      packet_out_len=send_packet(NULL, NULL, NULL); /* Get packet data size */
      if (packet_out_len < MINIMUM_FRAME_SIZE)
         packet_out_len = MINIMUM_FRAME_SIZE;   /* Adjust to minimum size */
      packet_out_len += PACKET_OVERHEAD;	/* Add layer 2 overhead */
      interval = ((ARP_UINT64)packet_out_len * 8 * 1000000) / bandwidth;
      if (verbose > 1) {
         warn_msg("DEBUG: pkt len=%u bytes, bandwidth=%u bps, interval=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *      Display initial message.
 */
   if (!plain_flag) {
      printf("Starting %s with %u hosts \n", PACKAGE_STRING, num_hosts);
   }
/*
 *      Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *      Main loop: send packets to all hosts in order until a response
 *      has been received or the host has exhausted its retry limit.
 *
 *      The loop exits when all hosts have either responded or timed out.
 */

/* printf("L%d - live_count=%d\n",__LINE__, live_count);*/


   reset_cum_err = 1;
   req_interval = interval;
   while (live_count) {
/*
 *      Obtain current time and calculate deltas since last packet and
 *      last packet to this host.
 */

      Gettimeofday(&now);

/*
 *      If the last packet was sent more than interval us ago, then we can
 *      potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= (unsigned)req_interval) {
/*
 *      If the last packet to this host was sent more than the current
 *      timeout for this host us ago, then we can potentially send a packet
 *      to it.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = (ARP_UINT64)1000000*diff.tv_sec + diff.tv_usec;
         if (host_timediff >= (*cursor)->timeout) {
            if (reset_cum_err) {
               cum_err = 0;
               req_interval = interval;
               reset_cum_err = 0;
            } else {
               cum_err += loop_timediff - interval;
               if (req_interval >= cum_err) {
                  req_interval = req_interval - cum_err;
               } else {
                  req_interval = 0;
               }
            }
            select_timeout = req_interval;
/*
 *      If we've exceeded our retry limit, then this host has timed out so
 *      remove it from the list. Otherwise, increase the timeout by the
 *      backoff factor if this is not the first packet sent to this host
 *      and send a packet.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host %s - Timeout",
                            my_ntoa((*cursor)->addr));
               remove_host(cursor);     /* Automatically calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = (ARP_UINT64)1000000*diff.tv_sec +
                                  diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tRemoving host %s - Catch-Up Timeout",
                                    my_ntoa((*cursor)->addr));
                        remove_host(cursor);
                     } else {
                        advance_cursor();
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = (ARP_UINT64)1000000*diff.tv_sec +
                                     diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {    /* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(pcap_handle, *cursor, &last_packet_time);
               advance_cursor();
            }
         } else {       /* We can't send a packet to this host yet */
/*
 *      Note that there is no point calling advance_cursor() here because if
 *      host n is not ready to send, then host n+1 will not be ready either.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;  /* Zero cumulative error */
         } /* End If */
      } else {          /* We can't send a packet yet */
         select_timeout = req_interval - loop_timediff;
      } /* End If */
      recvfrom_wto(pcap_fd, select_timeout, pcap_handle);
   } /* End While */

   if (!plain_flag) {
      printf("\n");        /* Ensure we have a blank line */
   }

   clean_up(pcap_handle);


   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000) / 1000.0;

   if (!plain_flag) {
      printf("Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec). %u responded\n",
             PACKAGE_STRING, num_hosts, elapsed_seconds,
             num_hosts/elapsed_seconds, responders);
   }

/*   if (interface_name!=NULL)
//       SAFE_FREE(if_name);
*/
   return NULL;
}




/*
 *	display_packet -- Check and display received packet
 *
 *	Inputs:
 *
 *	he		The host entry corresponding to the received packet
 *	arpei		ARP packet structure
 *	extra_data	Extra data after ARP packet (padding)
 *	extra_data_len	Length of extra data
 *	framing		Framing type (e.g. Ethernet II, LLC)
 *	vlan_id		802.1Q VLAN identifier, or -1 if not 802.1Q
 *	frame_hdr	The Ethernet frame header
 *	pcap_header	The PCAP header struct
 *
 *      Returns:
 *
 *      None.
 *
 *      This checks the received packet and displays details of what
 *      was received in the format: <IP-Address><TAB><Details>.
 */
int
display_packet(host_entry *he, arp_ether_ipv4 *arpei,
               const unsigned char *extra_data, size_t extra_data_len,
               int framing, int vlan_id, ether_hdr *frame_hdr,
               const struct pcap_pkthdr *pcap_header) {
   char *msg;
   char *cp;
   char *cp2;
   int nonzero=0;
/*
 *	Set msg to the IP address of the host entry and a tab.
 */
   msg = make_message("%s\t", my_ntoa(he->addr));

/*
 *	Decode ARP packet
 */
   cp = msg;
   msg = make_message("%s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", cp,
                      arpei->ar_sha[0], arpei->ar_sha[1],
                      arpei->ar_sha[2], arpei->ar_sha[3],
                      arpei->ar_sha[4], arpei->ar_sha[5]);
   free(cp);
/*
 *	Check that the source address in the Ethernet frame header is the same
 *	as ar$sha in the ARP packet, and display the Ethernet source address
 *	if it is different.
 */
   if ((memcmp(arpei->ar_sha, frame_hdr->src_addr, ETH_ALEN)) != 0) {
      cp = msg;
      msg = make_message("%s (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x)", cp,
                         frame_hdr->src_addr[0], frame_hdr->src_addr[1],
                         frame_hdr->src_addr[2], frame_hdr->src_addr[3],
                         frame_hdr->src_addr[4], frame_hdr->src_addr[5]);
      free(cp);
   }
/*
 *	Find vendor from hash table and add to message if quiet if not in
 *	effect.
 *
 *	We start with more specific matches (against larger parts of the
 *	hardware address), and work towards less specific matches until
 *	we find a match or exhaust all possible matches.
 */
   if (!quiet_flag) {
      char oui_string[13];	/* Space for full hw addr plus NULL */
      snprintf(oui_string, 13, "%.2X%.2X%.2X%.2X%.2X%.2X",
               arpei->ar_sha[0], arpei->ar_sha[1], arpei->ar_sha[2],
               arpei->ar_sha[3], arpei->ar_sha[4], arpei->ar_sha[5]);
      cp = msg;
      msg = make_message("%s\t%s", cp, "(Unknown)");
      free(cp);
/*
 *	Check that any data after the ARP packet is zero.
 *	If it is non-zero, and verbose is selected, then print the padding.
 */
      if (extra_data_len > 0) {
         unsigned i;
         const unsigned char *ucp = extra_data;

         for (i=0; i<extra_data_len; i++) {
            if (ucp[i] != '\0') {
               nonzero=1;
               break;
            }
         }
      }
      if (nonzero && verbose) {
         cp = msg;
         cp2 = hexstring(extra_data, extra_data_len);
         msg = make_message("%s\tPadding=%s", cp, cp2);
         free(cp2);
         free(cp);
      }
/*
 *	If the framing type is not Ethernet II, then report the framing type.
 */
      if (framing != FRAMING_ETHERNET_II) {
         cp = msg;
         if (framing == FRAMING_LLC_SNAP) {
            msg = make_message("%s (802.2 LLC/SNAP)", cp);
         }
         free(cp);
      }
/*
 *	If the packet uses 802.1Q VLAN tagging, report the VLAN ID.
 */
      if (vlan_id != -1) {
         cp = msg;
         msg = make_message("%s (802.1Q VLAN=%d)", cp, vlan_id);
         free(cp);
      }
/*
 *	If the ARP protocol type is not IP (0x0800), report it.
 *	This can occur with trailer encapsulation ARP replies.
 */
      if (ntohs(arpei->ar_pro) != 0x0800) {
         cp = msg;
         msg = make_message("%s (ARP Proto=0x%04x)", cp, ntohs(arpei->ar_pro));
         free(cp);
      }
/*
 *      If the host entry is not live, then flag this as a duplicate.
 */
      if (!he->live) {
         cp = msg;
         msg = make_message("%s (DUP: %u)", cp, he->num_recv);
         free(cp);
      }
/*
 *	If the rtt_flag is set, calculate and report the packet round-trip
 *	time.
 */
      if (rtt_flag) {
         struct timeval rtt;
         struct timeval pcap_timestamp;
         unsigned long rtt_us; /* round-trip time in microseconds */
/*
 * We can't pass a pointer to pcap_header->ts directly to timeval_diff
 * because it's not guaranteed to have the same size as a struct timeval.
 * E.g. OpenBSD 5.1 on amd64.
 */
         pcap_timestamp.tv_sec = pcap_header->ts.tv_sec;
         pcap_timestamp.tv_usec = pcap_header->ts.tv_usec;
         timeval_diff(&pcap_timestamp, &(he->last_send_time), &rtt);
         rtt_us = rtt.tv_sec * 1000000 + rtt.tv_usec;
         cp=msg;
         msg=make_message("%s\tRTT=%lu.%03lu ms", cp, rtt_us/1000, rtt_us%1000);
         free(cp);
      }
   }	/* End if (!quiet_flag) */
/*
 *	Print the message.
 */
   printf("%s\n", msg);
   free(msg);
   return 0;
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *
 *	Inputs:
 *
 *	pcap_handle	Pcap handle
 *	he		Host entry to send to. If NULL, then no packet is sent
 *	last_packet_time	Time when last packet was sent
 *
 *      Returns:
 *
 *      The size of the packet that was sent.
 *
 *      This constructs an appropriate packet and sends it to the host
 *      identified by "he" using the socket "s". It also updates the
 *	"last_send_time" field for the host entry.
 *
 */
int
send_packet(pcap_t *pcap_handle, host_entry *he,
            struct timeval *last_packet_time) {
   unsigned char buf[MAX_FRAME];
   size_t buflen;
   ether_hdr frame_hdr;
   arp_ether_ipv4 arpei;
   int nsent = 0;
/*
 *	Construct Ethernet frame header
 */
   memcpy(frame_hdr.dest_addr, target_mac, ETH_ALEN);
   memcpy(frame_hdr.src_addr, source_mac, ETH_ALEN);
   frame_hdr.frame_type = htons(eth_pro);
/*
 *	Construct the ARP Header.
 */
   memset(&arpei, 0, sizeof(arp_ether_ipv4));
   arpei.ar_hrd = htons(arp_hrd);
   arpei.ar_pro = htons(arp_pro);
   arpei.ar_hln = arp_hln;
   arpei.ar_pln = arp_pln;
   arpei.ar_op = htons(arp_op);
   memcpy(arpei.ar_sha, arp_sha, ETH_ALEN);
   memcpy(arpei.ar_tha, arp_tha, ETH_ALEN);
   if (arp_spa_is_tpa) {
      if (he) {
         arpei.ar_sip = he->addr.s_addr;
      }
   } else {
      arpei.ar_sip = arp_spa;
   }
   if (he)
      arpei.ar_tip = he->addr.s_addr;
/*
 *	Copy the required data into the output buffer "buf" and set "buflen"
 *	to the number of bytes in this buffer.
 */
   marshal_arp_pkt(buf, &frame_hdr, &arpei, &buflen, padding, padding_len);
/*
 *	If he is NULL, just return with the packet length.
 */
   if (he == NULL)
      return buflen;
/*
 *	Check that the host is live. Complain if not.
 */
   if (!he->live) {
      warn_msg("***\tsend_packet called on non-live host: SHOULDN'T HAPPEN");
      return 0;
   }
/*
 *	Update the last send times for this host.
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Send the packet.
 */
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host %s tmo %d", he->num_sent,
               my_ntoa(he->addr), he->timeout);
   {
      nsent = pcap_sendpacket(pcap_handle, buf, buflen);
   }
   if (nsent < 0)
   {
      err_sys("ERROR: failed to send packet");
	   return 0;
   }

   return buflen;
}

/*
 *      clean_up -- Protocol-specific Clean-Up routine.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This is called once after all hosts have been processed. It can be
 *      used to perform any tidying-up or statistics-displaying required.
 *      It does not have to do anything.
 */
void
clean_up(pcap_t *pcap_handle) {
   struct pcap_stat stats;

   //if (!plain_flag)
   {
      if (pcap_handle) {
         if ((pcap_stats(pcap_handle, &stats)) < 0)
	 {/*err_msg("pcap_stats: %s", pcap_geterr(pcap_handle));*/ return;}

        if (quiet_flag==0)
         printf("%u packets received by filter, %u packets dropped by kernel\n",
                stats.ps_recv, stats.ps_drop);
      }
   }
   if (pcap_dump_handle) {
      pcap_dump_close(pcap_dump_handle);
   }
   if (pcap_handle) {
      pcap_close(pcap_handle);
   }
   pcap_handle = 0;
   pcap_dump_handle = 0;
}


/*
 *      add_host_pattern -- Add one or more new host to the list.
 *
 *      Inputs:
 *
 *      pattern = The host pattern to add.
 *      host_timeout = Per-host timeout in ms.
 *
 *      Returns: None
 *
 *      This adds one or more new hosts to the list. The pattern argument
 *      can either be a single host or IP address, in which case one host
 *      will be added to the list, or it can specify a number of hosts with
 *      the IPnet/bits or IPstart-IPend formats.
 *
 *      The host_timeout and num_hosts arguments are passed unchanged to
 *	add_host().
 */
void
add_host_pattern(const char *pattern, unsigned host_timeout) {
   char *patcopy;
   struct in_addr in_val;
   struct in_addr mask_val;
   unsigned numbits;
   char *cp;
   uint32_t ipnet_val;
   uint32_t network;
   uint32_t mask;
   unsigned long hoststart;
   unsigned long hostend;
   unsigned i;
   uint32_t x;
   static int first_call=1;
   static regex_t iprange_pat;
   static regex_t ipslash_pat;
   static regex_t ipmask_pat;
   static const char *iprange_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
   static const char *ipslash_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+";
   static const char *ipmask_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
/*
 *	Compile regex patterns if this is the first time we've been called.
 */
   if (first_call) {
      int result;

      first_call = 0;
      if ((result=regcomp(&iprange_pat, iprange_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &iprange_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 iprange_pat_str, errbuf);
				  return;
      }
      if ((result=regcomp(&ipslash_pat, ipslash_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipslash_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipslash_pat_str, errbuf);
      }
      if ((result=regcomp(&ipmask_pat, ipmask_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipmask_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipmask_pat_str, errbuf);
      }
   }
/*
 *	Make a copy of pattern because we don't want to modify our argument.
 */
   patcopy = dupstr(pattern);

   if (!(regexec(&ipslash_pat, patcopy, 0, NULL, 0))) { /* IPnet/bits */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, '/');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to bits */
      if (!(inet_aton(patcopy, &in_val)))
      {err_msg("ERROR: %s is not a valid IP address", patcopy); free(patcopy); return;}
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      numbits=Strtoul(cp, 10);
      if (numbits<3 || numbits>32)
      {err_msg("ERROR: Number of bits in %s must be between 3 and 32",
                 pattern); free(patcopy); return;}
/*
 *	Construct 32-bit network bitmask from number of bits.
 */
      mask=0;
      for (i=0; i<numbits; i++)
         mask += 1 << i;
      mask = mask << (32-i);
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         snprintf(ipstr, 16, "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else if (!(regexec(&ipmask_pat, patcopy, 0, NULL, 0))) { /* IPnet:netmask */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, ':');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to netmask */
      if (!(inet_aton(patcopy, &in_val)))
      {err_msg("ERROR: %s is not a valid IP address", patcopy);  free(patcopy);return;}
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &mask_val)))
      {err_msg("ERROR: %s is not a valid netmask", patcopy);  free(patcopy);return;}
      mask=ntohl(mask_val.s_addr);	/* We need host byte order */
/*
 *	Calculate the number of bits in the network.
 */
      x = mask;
      for (numbits=0; x != 0; x>>=1) {
         if (x & 0x01) {
            numbits++;
         }
      }
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
/*   printf("L%d \t%d\t%d\n",__LINE__, hoststart, hostend);*/

      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         snprintf(ipstr, 16, "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else if (!(regexec(&iprange_pat, patcopy, 0, NULL, 0))) { /* IPstart-IPend */
/*
 *	Get IPstart and IPend as integers.
 */
      cp=strchr(patcopy, '-');
      *(cp++)='\0';	/* patcopy points to IPstart, cp points to IPend */
      if (!(inet_aton(patcopy, &in_val)))
      {err_msg("ERROR: %s is not a valid IP address", patcopy); free(patcopy);return;}
      hoststart=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &in_val)))
      {err_msg("ERROR: %s is not a valid IP address", cp); free(patcopy);return;}
      hostend=ntohl(in_val.s_addr);	/* We need host byte order */
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         int b1, b2, b3, b4;
         char ipstr[16];

         b1 = (i & 0xff000000) >> 24;
         b2 = (i & 0x00ff0000) >> 16;
         b3 = (i & 0x0000ff00) >> 8;
         b4 = (i & 0x000000ff);
         snprintf(ipstr, 16, "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, host_timeout, 1);
      }
   } else {	/* Single host or IP address */
      add_host(patcopy, host_timeout, numeric_flag);
   }
   free(patcopy);
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	host_name = The Name or IP address of the host.
 *	host_timeout = The initial host timeout in ms.
 *	numeric_only = 1 if the host name is definitely an IP address in
 *	               dotted quad format, or 0 if it may be a hostname or
 *	               IP address.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 */
void
add_host(const char *host_name, unsigned host_timeout, int numeric_only) {
   struct in_addr *hp=NULL;
   struct in_addr addr;
   host_entry *he;
/*   static int num_left=0;	/ * Number of free entries left */
   int result;
   char *ga_err_msg;

   if (numeric_only) {
      result = inet_pton(AF_INET, host_name, &addr);
      if (result < 0) {
         err_sys("ERROR: inet_pton failed for %s", host_name); return;
      } else if (result == 0) {
         warn_msg("WARNING: \"%s\" is not a valid IPv4 address - target ignored");
         return;
      }
   } else {
      hp = get_host_address(host_name, AF_INET, &addr, &ga_err_msg);
      if (hp == NULL) {
         warn_msg("WARNING: get_host_address failed for \"%s\": %s - target ignored",
                  host_name, ga_err_msg);
         return;
      }
   }

   if (!num_left) {	/* No entries left, allocate some more */
      if (helist)
         helist=(host_entry*)Realloc(helist, (num_hosts * sizeof(host_entry)) +
                        REALLOC_COUNT*sizeof(host_entry));
      else
         helist=(host_entry*)Malloc(REALLOC_COUNT*sizeof(host_entry));
      num_left = REALLOC_COUNT;
   }
   he = helist + num_hosts;	/* Would array notation be better? */
   num_hosts++;
   num_left--;

   memcpy(&(he->addr), &addr, sizeof(struct in_addr));
  he->live = 1;
   he->timeout = host_timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	inputs:
 *
 *	he = Pointer to host entry to remove.
 *
 *	Returns:
 *
 *	None.
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(host_entry **he) {
   if ((*he)->live) {
      (*he)->live = 0;
      live_count--;
      if (*he == *cursor)
         advance_cursor();
   } else {
      if (verbose > 1)
         warn_msg("***\tremove_host called on non-live host: SHOULDN'T HAPPEN");
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(void) {
   if (live_count) {
      do {
         if (cursor == (helistptr+(num_hosts-1)))
            cursor = helistptr;	/* Wrap round to beginning */
         else
            cursor++;
      } while (!(*cursor)->live);
   } /* End If */
}

/*
 *	find_host	-- Find a host in the list
 *
 *	Inputs:
 *
 *	he 	Pointer to the current position in the list. Search runs
 *		backwards starting from this point.
 *	addr 	The source IP address that the packet came from.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 *
 *	This routine finds the host by IP address by comparing "addr" against
 *	"he->addr" for each entry in the list.
 */
host_entry *
find_host(host_entry **he, struct in_addr *addr) {
   host_entry **p;
   int found = 0;
   unsigned iterations = 0;	/* Used for debugging */
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (*he == NULL) {
      return NULL;
   }
/*
 *	Try to match against out host list.
 */
   p = he;

   do {
      iterations++;
      if ((*p)->addr.s_addr == addr->s_addr) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1);	/* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);


   if (found)
      return *p;
   else
      return NULL;
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Inputs:
 *
 *	sock_fd		= Socket file descriptor.
 *	tmo		= Select timeout in us.
 *	pcap_handle 	= pcap handle
 *
 *	Returns:
 *
 *	None.
 *
 *	If the socket file descriptor is -1, this indicates that we are
 *	reading packets from a pcap file and there is no associated network
 *	device.
 */
void
recvfrom_wto(int sock_fd, int tmo, pcap_t *pcap_handle) {
   fd_set readset;
   struct timeval to;
   int n;

   FD_ZERO(&readset);
   if (sock_fd >= 0)
      FD_SET(sock_fd, &readset);
   to.tv_sec  = tmo/1000000;
   to.tv_usec = (tmo - 1000000*to.tv_sec);
   n = select(sock_fd+1, &readset, NULL, NULL, &to);
   if (n < 0) {
      err_sys("select"); return;
   } else if (n == 0 && sock_fd >= 0) {
/*
 * For the BPF pcap implementation, we call pcap_dispatch() even if select
 * times out. This is because on many BPF implementations, select() doesn't
 * indicate if there is input waiting on a BPF device.
 */
#ifdef ARP_PCAP_BPF
      if ((pcap_dispatch(pcap_handle, -1, callback, NULL)) == -1)
         {err_sys("pcap_dispatch: %s\n", pcap_geterr(pcap_handle)); return;}
#endif
      return;	/* Timeout */
   }
/*
 * Call pcap_dispatch() to process the packet if we are reading packets.
 */
   if (pcap_handle) {
      if ((pcap_dispatch(pcap_handle, -1, callback, NULL)) == -1)
      {err_sys("pcap_dispatch: %s\n", pcap_geterr(pcap_handle));return;}
   }
}

/*
 *	dump_list -- Display contents of host list for debugging
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 */
void
dump_list(void) {
   unsigned i;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\n");
   for (i=0; i<num_hosts; i++)
      printf("%u\t%s\n", i+1, my_ntoa(helistptr[i]->addr));
   printf("\nTotal of %u host entries.\n\n", num_hosts);
}

/*
 * callback -- pcap callback function
 *
 * Inputs:
 *
 *	args		Special args (not used)
 *	header		pcap header structure
 *	packet_in	The captured packet
 *
 * Returns:
 *
 * None
 */
void
callback(u_char *args,
         const struct pcap_pkthdr *header, const u_char *packet_in) {
   arp_ether_ipv4 arpei;
   ether_hdr frame_hdr;
   int n = header->caplen;
   struct in_addr source_ip;
   host_entry *temp_cursor;
   unsigned char extra_data[MAX_FRAME];
   size_t extra_data_len;
   int vlan_id;
   int framing;
   struct stringnode *it;
   struct ulongnode *itl;

    (void)(args);
/*
 *      Check that the packet is large enough to decode.
 */
   if (n < ETHER_HDR_SIZE + ARP_PKT_SIZE) {
      printf("%d byte packet too short to decode\n", n);
      return;
   }
/*
 *	Unmarshal packet buffer into structures and determine framing type
 */
   framing = unmarshal_arp_pkt(packet_in, n, &frame_hdr, &arpei, extra_data,
                               &extra_data_len, &vlan_id);
/*
 *	Determine source IP address.
 */
   source_ip.s_addr = arpei.ar_sip;
/*
 *	We've received a response. Try to match up the packet by IP address
 *
 *	We should really start searching at the host before the cursor, as we
 *	know that the host to match cannot be the one at the cursor position
 *	because we call advance_cursor() after sending each packet. However,
 *	the time saved is minimal, and it's not worth the extra complexity.
 */
   temp_cursor=find_host(cursor, &source_ip);
   if (temp_cursor) {
/*
 *	We found an IP match for the packet.
 */
/*
 *	Display the packet and increment the number of responders if
 *	the entry is "live" or we are not ignoring duplicates.
 */
      temp_cursor->num_recv++;
      if (verbose > 1)
         warn_msg("---\tReceived packet #%u from %s",
                  temp_cursor->num_recv ,my_ntoa(source_ip));
      if ((temp_cursor->live || !ignore_dups)) {
         if (pcap_dump_handle) {
            pcap_dump((unsigned char *)pcap_dump_handle, header, packet_in);
         }

        /* add to the data sink list */
        it = (struct stringnode*)Malloc(sizeof(struct stringnode));
        it->str = make_message("%s",my_ntoa(temp_cursor->addr));
        it->prev = g_sinklist;
        g_sinklist = it;

        itl = (struct ulongnode*)Malloc(sizeof(struct ulongnode));
        itl->addr = temp_cursor->addr.s_addr;
        itl->prev = g_sinklistaddr;
        g_sinklistaddr = itl;

        if (quiet_flag==0)
         display_packet(temp_cursor, &arpei, extra_data, extra_data_len,
                        framing, vlan_id, &frame_hdr, header);
         responders++;
      }
      if (verbose > 1)
         warn_msg("---\tRemoving host %s - Received %d bytes",
                  my_ntoa(source_ip), n);
      remove_host(&temp_cursor);
   } else {
/*
 *	The received packet is not from an IP address in the list
 *	Issue a message to that effect and ignore the packet.
 */
      if (verbose)
         warn_msg("---\tIgnoring %d bytes from unknown host %s", n, my_ntoa(source_ip));
   }
}

/*
 *	get_host_address -- Obtain target host IP address
 *
 *	Inputs:
 *
 *	name		The name to lookup
 *	af		The address family
 *	addr		Pointer to the IP address buffer
 *	error_msg	The error message, or NULL if no problem.
 *
 *	Returns:
 *
 *	Pointer to the IP address, or NULL if an error occurred.
 *
 *	This function is basically a wrapper for getaddrinfo().
 */
struct in_addr *
get_host_address(const char *name, int af, struct in_addr *addr,
                 char **error_msg) {
   static char err[MAXLINE];
   static struct in_addr ipa;

   struct addrinfo *res;
   struct addrinfo hints;
   struct sockaddr_in sa_in;
   int result;

   if (addr == NULL)	/* Use static storage if no buffer specified */
      addr = &ipa;

   memset(&hints, 0, sizeof(struct addrinfo));
   if (af == AF_INET) {
      hints.ai_family = AF_INET;
   } else {
      err_msg("get_host_address: unknown address family: %d", af);
   }

   result = getaddrinfo(name, NULL, &hints, &res);
   if (result != 0) {	/* Error occurred */
      snprintf(err, MAXLINE, "%s", gai_strerror(result));
      *error_msg = err;
      return NULL;
   }

   memcpy(&sa_in, res->ai_addr, sizeof(struct sockaddr_in));
   memcpy(addr, &sa_in.sin_addr, sizeof(struct in_addr));

   freeaddrinfo(res);

   *error_msg = NULL;
   return addr;
}

/*
 *	my_ntoa -- IPv6 compatible inet_ntoa replacement
 *
 *	Inputs:
 *
 *	addr	The IP address
 *
 *	Returns:
 *
 *	Pointer to the string representation of the IP address.
 *
 *	This currently only supports IPv4.
 */
const char *
my_ntoa(struct in_addr addr) {
   static char ip_str[MAXLINE];
   const char *cp;

   cp = inet_ntop(AF_INET, &addr, ip_str, MAXLINE);

   return cp;
}
const char *
my_ntoa2(const uint32_t add) {
    struct in_addr addr;
    addr.s_addr = add;
   return my_ntoa(addr);
}

/*
 *	marshal_arp_pkt -- Marshal ARP packet from struct to buffer
 *
 *	Inputs:
 *
 *	buffer		Pointer to the output buffer
 *	frame_hdr	The Ethernet frame header
 *	arp_pkt		The ARP packet
 *	buf_siz		The size of the output buffer
 *	frame_padding	Any padding to add after the ARP payload.
 *	frame_padding_len	The length of the padding.
 *
 *	Returns:
 *
 *	None
 */
void
marshal_arp_pkt(unsigned char *buffer, ether_hdr *frame_hdr,
                arp_ether_ipv4 *arp_pkt, size_t *buf_siz,
                const unsigned char *frame_padding, size_t frame_padding_len) {
   unsigned char llc_snap[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
   unsigned char vlan_tag[] = {0x81, 0x00, 0x00, 0x00};
   unsigned char *cp;
   size_t packet_size;

   cp = buffer;
/*
 *	Set initial packet length to the size of an Ethernet frame using
 *	Ethernet-II format plus the size of the ARP data. This may be
 *	increased later by LLC/SNAP frame format or padding after the
 *	ARP data.
 */
   packet_size = sizeof(frame_hdr->dest_addr) + sizeof(frame_hdr->src_addr) +
                 sizeof(frame_hdr->frame_type) +
                 sizeof(arp_pkt->ar_hrd) + sizeof(arp_pkt->ar_pro) +
                 sizeof(arp_pkt->ar_hln) + sizeof(arp_pkt->ar_pln) +
                 sizeof(arp_pkt->ar_op)  + sizeof(arp_pkt->ar_sha) +
                 sizeof(arp_pkt->ar_sip) + sizeof(arp_pkt->ar_tha) +
                 sizeof(arp_pkt->ar_tip);
/*
 *	Copy the Ethernet frame header to the buffer.
 */
   memcpy(cp, &(frame_hdr->dest_addr), sizeof(frame_hdr->dest_addr));
   cp += sizeof(frame_hdr->dest_addr);
   memcpy(cp, &(frame_hdr->src_addr), sizeof(frame_hdr->src_addr));
   cp += sizeof(frame_hdr->src_addr);
/*
 *	Add 802.1Q tag if we are using VLAN tagging
 */
   if (ieee_8021q_vlan != -1) {
      uint16_t tci;

      tci = htons(ieee_8021q_vlan);
      memcpy(cp, vlan_tag, sizeof(vlan_tag));
      memcpy(cp+2, &tci, sizeof(tci));
      cp += sizeof(vlan_tag);
      packet_size += sizeof(vlan_tag);
   }
   if (llc_flag) {	/* With 802.2 LLC framing, type field is frame size */
      uint16_t frame_size;

      frame_size=htons(packet_size + sizeof(llc_snap));
      memcpy(cp, &(frame_size), sizeof(frame_size));
   } else {		/* Normal Ethernet-II framing */
      memcpy(cp, &(frame_hdr->frame_type), sizeof(frame_hdr->frame_type));
   }
   cp += sizeof(frame_hdr->frame_type);
/*
 *	Add IEEE 802.2 LLC and SNAP fields if we are using LLC frame format.
 */
   if (llc_flag) {
      memcpy(cp, llc_snap, sizeof(llc_snap));
      memcpy(cp+6, &(frame_hdr->frame_type), sizeof(frame_hdr->frame_type));
      cp += sizeof(llc_snap);
      packet_size += sizeof(llc_snap);
   }
/*
 *	Add the ARP data.
 */
   memcpy(cp, &(arp_pkt->ar_hrd), sizeof(arp_pkt->ar_hrd));
   cp += sizeof(arp_pkt->ar_hrd);
   memcpy(cp, &(arp_pkt->ar_pro), sizeof(arp_pkt->ar_pro));
   cp += sizeof(arp_pkt->ar_pro);
   memcpy(cp, &(arp_pkt->ar_hln), sizeof(arp_pkt->ar_hln));
   cp += sizeof(arp_pkt->ar_hln);
   memcpy(cp, &(arp_pkt->ar_pln), sizeof(arp_pkt->ar_pln));
   cp += sizeof(arp_pkt->ar_pln);
   memcpy(cp, &(arp_pkt->ar_op), sizeof(arp_pkt->ar_op));
   cp += sizeof(arp_pkt->ar_op);
   memcpy(cp, &(arp_pkt->ar_sha), sizeof(arp_pkt->ar_sha));
   cp += sizeof(arp_pkt->ar_sha);
   memcpy(cp, &(arp_pkt->ar_sip), sizeof(arp_pkt->ar_sip));
   cp += sizeof(arp_pkt->ar_sip);
   memcpy(cp, &(arp_pkt->ar_tha), sizeof(arp_pkt->ar_tha));
   cp += sizeof(arp_pkt->ar_tha);
   memcpy(cp, &(arp_pkt->ar_tip), sizeof(arp_pkt->ar_tip));
   cp += sizeof(arp_pkt->ar_tip);
/*
 *	Add padding if specified
 */
   if (frame_padding != NULL) {
      size_t safe_padding_len;

      safe_padding_len = frame_padding_len;
      if (packet_size + frame_padding_len > MAX_FRAME) {
         safe_padding_len = MAX_FRAME - packet_size;
      }
      memcpy(cp, frame_padding, safe_padding_len);
      cp += safe_padding_len;
      packet_size += safe_padding_len;
   }
   *buf_siz = packet_size;
}

/*
 *	unmarshal_arp_pkt -- Un Marshal ARP packet from buffer to struct
 *
 *	Inputs:
 *
 *	buffer		Pointer to the input buffer
 *	buf_len		Length of input buffer
 *	frame_hdr	The ethernet frame header
 *	arp_pkt		The arp packet data
 *	extra_data	Any extra data after the ARP data (typically padding)
 *	extra_data_len	Length of extra data
 *	vlan_id		802.1Q VLAN identifier
 *
 *	Returns:
 *
 *	An integer representing the data link framing:
 *	0 = Ethernet-II
 *	1 = 802.3 with LLC/SNAP
 *
 *	extra_data and extra_data_len are only calculated and returned if
 *	extra_data is not NULL.
 *
 *	vlan_id is set to -1 if the packet does not use 802.1Q tagging.
 */
int
unmarshal_arp_pkt(const unsigned char *buffer, size_t buf_len,
                  ether_hdr *frame_hdr, arp_ether_ipv4 *arp_pkt,
                  unsigned char *extra_data, size_t *extra_data_len,
                  int *vlan_id) {
   const unsigned char *cp;
   int framing=FRAMING_ETHERNET_II;

   cp = buffer;
/*
 *	Extract the Ethernet frame header data
 */
   memcpy(&(frame_hdr->dest_addr), cp, sizeof(frame_hdr->dest_addr));
   cp += sizeof(frame_hdr->dest_addr);
   memcpy(&(frame_hdr->src_addr), cp, sizeof(frame_hdr->src_addr));
   cp += sizeof(frame_hdr->src_addr);
/*
 *	Check for 802.1Q VLAN tagging, indicated by a type code of
 *	0x8100 (TPID).
 */
   if (*cp == 0x81 && *(cp+1) == 0x00) {
      uint16_t tci;
      cp += 2;	/* Skip TPID */
      memcpy(&tci, cp, sizeof(tci));
      cp += 2;	/* Skip TCI */
      *vlan_id = ntohs(tci);
      *vlan_id &= 0x0fff;	/* Mask off PRI and CFI */
   } else {
      *vlan_id = -1;
   }
   memcpy(&(frame_hdr->frame_type), cp, sizeof(frame_hdr->frame_type));
   cp += sizeof(frame_hdr->frame_type);
/*
 *	Check for an LLC header with SNAP. If this is present, the 802.2 LLC
 *	header will contain DSAP=0xAA, SSAP=0xAA, Control=0x03.
 *	If this 802.2 LLC header is present, skip it and the SNAP header
 */
   if (*cp == 0xAA && *(cp+1) == 0xAA && *(cp+2) == 0x03) {
      cp += 8;	/* Skip eight bytes */
      framing = FRAMING_LLC_SNAP;
   }
/*
 *	Extract the ARP packet data
 */
   memcpy(&(arp_pkt->ar_hrd), cp, sizeof(arp_pkt->ar_hrd));
   cp += sizeof(arp_pkt->ar_hrd);
   memcpy(&(arp_pkt->ar_pro), cp, sizeof(arp_pkt->ar_pro));
   cp += sizeof(arp_pkt->ar_pro);
   memcpy(&(arp_pkt->ar_hln), cp, sizeof(arp_pkt->ar_hln));
   cp += sizeof(arp_pkt->ar_hln);
   memcpy(&(arp_pkt->ar_pln), cp, sizeof(arp_pkt->ar_pln));
   cp += sizeof(arp_pkt->ar_pln);
   memcpy(&(arp_pkt->ar_op), cp, sizeof(arp_pkt->ar_op));
   cp += sizeof(arp_pkt->ar_op);
   memcpy(&(arp_pkt->ar_sha), cp, sizeof(arp_pkt->ar_sha));
   cp += sizeof(arp_pkt->ar_sha);
   memcpy(&(arp_pkt->ar_sip), cp, sizeof(arp_pkt->ar_sip));
   cp += sizeof(arp_pkt->ar_sip);
   memcpy(&(arp_pkt->ar_tha), cp, sizeof(arp_pkt->ar_tha));
   cp += sizeof(arp_pkt->ar_tha);
   memcpy(&(arp_pkt->ar_tip), cp, sizeof(arp_pkt->ar_tip));
   cp += sizeof(arp_pkt->ar_tip);

   if (extra_data != NULL) {
      int length;

      length = buf_len - (cp - buffer);
      if (length > 0) {		/* Extra data after ARP packet */
         memcpy(extra_data, cp, length);
      }
      *extra_data_len = length;
   }

   return framing;
}


/*
 *      get_source_ip   -- Get IP address associated with given interface
 *
 *      Inputs:
 *
 *      interface_name  The name of the network interface
 *      ip_addr         (output) The IP Address associated with the device
 *
 *      Returns:
 *
 *      Zero on success, or -1 on failure.
 */
int
get_source_ip(const char *interface_name, uint32_t *ip_addr) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *alldevsp;
   pcap_if_t *device;
   pcap_addr_t *addr;
   struct sockaddr *sa;
   struct sockaddr_in *sin = NULL;

   if ((pcap_findalldevs(&alldevsp, errbuf)) != 0) {
      printf("pcap_findalldevs: %s\n", errbuf);
   }

   device=alldevsp;
   while (device != NULL && (strcmp(device->name,interface_name) != 0)) {
      device=device->next;
   }
   if (device == NULL) {
      warn_msg("ERROR: Could not find interface: %s", interface_name);
      err_msg("ERROR: Check that the interface exists and is up");
	   return -1;
   }

   for (addr=device->addresses; addr != NULL; addr=addr->next) {
      sa = addr->addr;
      if (sa->sa_family == AF_INET) {
         sin = (struct sockaddr_in *) sa;
         break;
      }
   }
   if (sin == NULL) {
      return -1;
   }

   memcpy(ip_addr, &(sin->sin_addr.s_addr), sizeof(uint32_t));

   pcap_freealldevs(alldevsp);

   return 0;
}

/*
***********************************************************************
***********************************************************************
*/
const socklen_t g_addr_size = sizeof(struct sockaddr_in);
struct timeval g_wait_time;
unsigned char g_ipbytes[4];

//static pthread_mutex_t g_thread_id_lock;


typedef struct _tagcheckdatasink_data
{
    int clientSocket;
    struct sockaddr_in serverAddr;
    uint32_t  addr_to_check;
    pthread_t thread_id;
    pthread_mutex_t lock;
    int found;
    char buffer[37];
} CheckDataSink_Data;

#define g_nthreads 50
CheckDataSink_Data  *g_checkdatasink_data;

void set_wait_time(const int sec, const int micro_sec)
{
    int i;
	g_wait_time.tv_sec = sec;  /* Seconds to Timeout */
	g_wait_time.tv_usec = micro_sec;  /* Not init'ing this can cause strange errors */
	for(i=0;i<g_nthreads;i++)
	{
        setsockopt (g_checkdatasink_data[i].clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&g_wait_time, sizeof(struct timeval));
        setsockopt (g_checkdatasink_data[i].clientSocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&g_wait_time, sizeof(struct timeval));
    }
}

int checkdatasink_endall(const int ret)
{
    int i;
	for(i=0;i<g_nthreads;i++)
	{
        if (g_checkdatasink_data[i].clientSocket!=-1)
        {
            close(g_checkdatasink_data[i].clientSocket);
            g_checkdatasink_data[i].clientSocket = -1;
        }
        pthread_mutex_destroy(&g_checkdatasink_data[i].lock);
    }
    free(g_checkdatasink_data);
    cleanup();
    return ret;
}

int checkdatasink_begin(const int ithread)
{
    //printf("L%d: init [%d], %s \r",__LINE__, ithread, strerror(errno));

    memset(&g_checkdatasink_data[ithread], 0, sizeof(CheckDataSink_Data));
    //printf("L%d: Here? \n",__LINE__);

    pthread_mutex_init(&g_checkdatasink_data[ithread].lock, NULL);

	/*---- Create the socket. The three arguments are: ----*/
	/* 1) Internet domain: PF_INET or AF_INET? 2) Stream socket 3) Default protocol (TCP in this case) */
	g_checkdatasink_data[ithread].clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//	int optval = 1;
//    setsockopt(g_checkdatasink_data[ithread].clientSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int));

	/*---- Configure settings of the server address struct ----*/
	/* Address family = Internet */
	g_checkdatasink_data[ithread].serverAddr.sin_family = AF_INET;
	/* Set port number, using htons function to use proper byte order */
	g_checkdatasink_data[ithread].serverAddr.sin_port = htons(7891);
	/* Set IP address to localhost */
	/*g_checkdatasink_data.serverAddr.sin_addr.s_addr = inet_addr(iface);*//*"127.0.0.1");*/
	/* Set all bits of the padding field to 0 */
	//memset(g_checkdatasink_data[ithread].serverAddr.sin_zero, '\0', sizeof(g_checkdatasink_data[ithread].serverAddr.sin_zero));

    //printf("L%d: init  end [%d], %s \n",__LINE__, ithread, strerror(errno));

    return 0;
}

void *checkdatasink_test(void *pdata)
{
    CheckDataSink_Data *pcheckdatasink_data = (CheckDataSink_Data *) pdata;
    pthread_mutex_lock(&pcheckdatasink_data->lock);
    //printf("[%d]\n", pcheckdatasink_data->found);
    pcheckdatasink_data->found = 0;
    pthread_mutex_unlock(&pcheckdatasink_data->lock);
    return NULL;
}

void *checkdatasink(void *pdata)
{
   CheckDataSink_Data *pcheckdatasink_data = (CheckDataSink_Data *) pdata;

    //pthread_mutex_lock(&pcheckdatasink_data->lock);
	/*---- Configure settings of the server address struct ----*/
	/* Set IP address to localhost */
	pcheckdatasink_data->serverAddr.sin_addr.s_addr = pcheckdatasink_data->addr_to_check;
	/*inet_addr(pcheckdatasink_data->addr_to_check);*//*"127.0.0.1");*/
    //pthread_mutex_unlock(&pcheckdatasink_data->lock);

/*
	"c67e7c76-1104-4afd-ab97-2b714a1bfd6a"
	"7784c4d9-b39f-4f7b-81c9-8b1fc30fa342"
*/

	/*---- Connect the socket to the server using the address struct ----*/
	if ( connect(pcheckdatasink_data->clientSocket, (struct sockaddr *) &pcheckdatasink_data->serverAddr, g_addr_size) == 0 )
	{
        /* Send the word to the server */
        if (send(pcheckdatasink_data->clientSocket, "c67e7c76-1104-4afd-ab97-2b714a1bfd6a", 36, 0) == 36)
        {
            /* Wait for the server to answer */
            /*---- Read the message from the server into the buffer ----*/
            if (recv(pcheckdatasink_data->clientSocket, pcheckdatasink_data->buffer, 36, 0/*MSG_PEEK*/) == 36)
            {
                /* check the message */
                if (memcmp(pcheckdatasink_data->buffer, "7784c4d9-b39f-4f7b-81c9-8b1fc30fa342",36) == 0)
                {
                    /* Send the mac and ip addresses of the reader to the server */
                    if (send(pcheckdatasink_data->clientSocket, source_mac, 6, 0) == 6)
                    {
                        if (send(pcheckdatasink_data->clientSocket, g_ipbytes, 4, 0) == 4)
                        {
                            pthread_mutex_lock(&pcheckdatasink_data->lock);
                            pcheckdatasink_data->found = 1;
                            pthread_mutex_unlock(&pcheckdatasink_data->lock);
                            return NULL;
                        }
                    }
                }
            }
        }
    }
    //else{printf("L%d: [%d]",__LINE__, ithread);fflush(stdout);}

    pthread_mutex_lock(&pcheckdatasink_data->lock);
    pcheckdatasink_data->found = 0;
    pthread_mutex_unlock(&pcheckdatasink_data->lock);
    return NULL;
}


int getactivedatasink(char *host)
{
    int i, k, ithread, ret=0;
	plain_flag = 1;
	quiet_flag = 0;

    g_checkdatasink_data = (CheckDataSink_Data*)malloc(g_nthreads*sizeof(CheckDataSink_Data));

    for(ithread=0;ithread<g_nthreads;ithread++)
        checkdatasink_begin(ithread);

    if (quiet_flag==0)
        printf("L%d: looking for host<%s>, err: %s \n",__LINE__, host , strerror(errno));
	if (strlen(host)>0)
	if (gethostbyname (host)!= NULL)
	{
        ithread = 0;
        set_wait_time(5, 0);
        for(i=0;i<3;i++)
        {
            g_checkdatasink_data[ithread].addr_to_check  = inet_addr(host);
            checkdatasink(&g_checkdatasink_data[ithread]);
            if (g_checkdatasink_data[ithread].found==1)
                return checkdatasink_endall(1);
        }
	}

	findsink(if_name);

    if (quiet_flag==0)
        printf("L%d: search done.\n",__LINE__);
    if (quiet_flag==0)
        printf("L%d: err: %s \n",__LINE__, strerror(errno));
    errno = 0;

	/* get ip address */
	g_ipbytes[0] = arp_spa & 0xFF;
	g_ipbytes[1] = (arp_spa >> 8) & 0xFF;
	g_ipbytes[2] = (arp_spa >> 16) & 0xFF;
	g_ipbytes[3] = (arp_spa >> 24) & 0xFF;

	set_wait_time(2, 0);

    //pthread_mutex_init(&g_thread_id_lock, NULL);

    struct stringnode *it = g_sinklist;
    struct ulongnode *itl = g_sinklistaddr;
/*
    for(i=0;i<500;i++)
    {
        g_sinklist = (struct stringnode*)Malloc(sizeof(struct stringnode));
        g_sinklist->str = make_message("192.168.0.13");
        g_sinklist->prev = it;
        it = g_sinklist;
        g_sinklistaddr = (struct ulongnode*)Malloc(sizeof(struct ulongnode));
        g_sinklistaddr->addr = inet_addr(g_sinklist->str);
        g_sinklistaddr->prev = itl;
        itl = g_sinklistaddr;
    }
    */
    i=-1;
    ithread=0;
	while(it!=NULL)
	{
        pthread_mutex_lock(&g_checkdatasink_data[ithread].lock);
        k = g_checkdatasink_data[ithread].found;
        pthread_mutex_unlock(&g_checkdatasink_data[ithread].lock);
        if (k==0)
        {
            if (quiet_flag==0)
                    printf("L%d: thread[%d]: checking %s ... \r",__LINE__, ithread, it->str);
            g_checkdatasink_data[ithread].addr_to_check = itl->addr;
            g_checkdatasink_data[ithread].found = 2;
//            checkdatasink(&ithread);
            if (g_checkdatasink_data[ithread].thread_id!=0)
                pthread_join(g_checkdatasink_data[ithread].thread_id, NULL);
            if (pthread_create( &g_checkdatasink_data[ithread].thread_id , NULL ,  checkdatasink , &g_checkdatasink_data[ithread])==0)
            {
                it = it->prev;
                itl = itl->prev;
            }
            //sleep(1);
        }
        else if (k==1)
        {
            // server founded
            i = ithread;
            break;
        }
        /* go to check other threads */
        if (++ithread == g_nthreads) {ithread=0;}
        //printf("L%d: Looking at thread[%d]...\n",__LINE__, ithread);
        //fflush(stdout);
	}

    // wait for all other threads to terminate
	for(ithread=0;ithread<g_nthreads;ithread++)
    {
        if (g_checkdatasink_data[ithread].thread_id==0) continue;
        pthread_join(g_checkdatasink_data[ithread].thread_id, NULL);
        /*
        pthread_mutex_lock(&g_checkdatasink_data[ithread].lock);
        k = g_checkdatasink_data[ithread].found;
        pthread_mutex_unlock(&g_checkdatasink_data[ithread].lock);
        if (k==2)
        {
            if (quiet_flag==0)
                printf("L%d: Waiting for thread %d ... \n",__LINE__,ithread);
            //fflush(stdout);
            pthread_join(g_checkdatasink_data[ithread].thread_id, NULL);
        }
        */
    }
    // Now all threads have finished
    if (i<0)
    {
        for(ithread=0;ithread<g_nthreads;ithread++)
        {
            if (g_checkdatasink_data[ithread].found == 1)
            {
                memset(host, '\0', 16);
                strcpy(host, my_ntoa2(g_checkdatasink_data[ithread].addr_to_check));
                printf("A server found at %s. ", host);
                ret = 1;
                break;
            }
        }
    }
    else
    {
        if (g_checkdatasink_data[i].found == 1)
        {
            memset(host, '\0', 16);
            strcpy(host, my_ntoa2(g_checkdatasink_data[ithread].addr_to_check));
			printf("A server found at %s. ", host);
            ret = 1;
        }
    }

    /* destroy the lock */
    //pthread_mutex_destroy(&g_thread_id_lock);

    if (quiet_flag==0)
        printf("L%d: err: %s \n",__LINE__, strerror(errno));
	fflush(stdout);
    return checkdatasink_endall(ret);
}

/*}; / * namespace findsink* / */
/*
// test function
int main()
{
    char sink[16];
    memset(sink, '\0', 16);
    int i;

	plain_flag = 1;
	quiet_flag = 0;

    for(i=0;i<100;i++)
    {
        printf("L%d: begins (%d): \n",__LINE__, i);
        getactivedatasink(sink);
        printf("L%d: ends (%d). \n",__LINE__, i);
        //sleep(1);
    }

    return 0;
}
*/
