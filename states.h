#ifndef __STATES_H__
#define __STATES_H__


/*  G L O B A L S  ************************************************************/
static PV pv;                 /* program vars (command line args) */
static char *pktidx;          /* index ptr for the current packet */
static FILE *log_ptr;         /* log file ptr */
static FILE *alert;           /* alert file ptr */
static FILE *binfrag_ptr;     /* binary fragment file ptr */
static FILE *binlog_ptr;      /* binary output file ptr */
static int thiszone;          /* time zone info */
static PacketCount pc;        /* packet count information */
static u_long netmasks[33];   /* precalculated netmask array */
static char protocol_names[18][6];
static int MTU;               /* Maximum xfer unit */

static ListHead Alert;      /* Alert Block Header */
static ListHead Log;        /* Log Block Header */
static ListHead Pass;       /* Pass Block Header */

static RuleTreeNode *rtn_tmp;  /* temp data holder */
static OptTreeNode *otn_tmp;   /* OptTreeNode temp ptr */

static int file_line;      /* current line being processed in the rules file */
static int rule_count;     /* number of rules generated */
static int head_count;     /* number of header blocks (chain heads?) */
static int opt_count;      /* number of chains */

#ifdef BENCHMARK
static int check_count;    /* number of tests for a given rule to determine a match */
static int cmpcount;       /* compare counter */
#endif

static char *data_dump_buffer;  /* printout buffer for PrintNetData */
static int dump_ready;          /* flag to indicate status of printout buffer */
static int dump_size;



#endif