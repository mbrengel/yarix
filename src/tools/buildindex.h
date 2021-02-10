/*
 * number of read worker threads reading input files (stage 1)
 */
#define NUM_READ_WORKERS 8

/* 
 * number of threads per read worker thread that will extract
 * ngrams from the read input file (stage 1)
 */
#define NUM_NGRAM_WORKERS 16

/* 
 * number of threads for stage2 that will convert prefiles into PLs
 *
 * NOTE: increasing this number will require *SIGNIFICANTLY*
 *       more dynamically-allocated RAM (about 7 * `MAX_PLEs` bytes (!) per thread).
 *       If you system is short on RAM, consider decreasing this
 *       value to avoid malloc() failures.
 *
 * Some advise on good settings, depending on the RAM size in GB:
 *      >= 64 GB:   NUM_STAGE2_WORKERS = 2
 *      >= 128 GB:  NUM_STAGE2_WORKERS = 4
 *      >= 256 GB:  NUM_STAGE2_WORKERS = 6
 */
#define NUM_STAGE2_WORKERS 6

#define MAX_IN_MEM_PL_SIZE 1024
#define MAXUINT32 4294967295

/* increasing these constants will results in SIGNIFICANY higher memory usage */
#define MAX_INPUT_FILE_SIZE (size_t) 2 * 1024 * 1024 * 1024 // 2 GiB
#define MAX_PLEs (uint64_t) 4 * 1000 * 1000 * 1000 // 4B
#define MAX_PL_SIZE MAX_PLEs

#define MAX_NUM_FILE_NAMES 1000 * 1000 + 1
#define MAX_FILENAME_LENGTH 512

/* used to calculcate progress speed every N processed files */
#define CHECKPOINT_INTERVAL 1000
        
#define get_C(i) (entries[i].ngram_suffix >> 8)
#define get_D(i) (entries[i].ngram_suffix & 0xFF)

typedef struct __attribute__((packed)) {
    uint16_t ngram_suffix;
    uint32_t fid;
} PLE;

typedef struct __attribute__((packed)) {
    uint64_t offsets[256];
    //char data[];
} PL;

typedef struct _threaddata {
    uint32_t tid;
    uint32_t fid;
    size_t size;
    char *buf;
} t_threaddata;

typedef struct _hash_ngram {
    uint32_t ngram;            /* key */
    UT_hash_handle hh;         /* makes this structure hashable */
} hash_ngram;



/*
 * OPTIONS TO IMPLEMENT GROUPING:
 *
 * a) convert PLEs into groups while/after parsing them
 *    PRO: easy to keep current code
 *    CON: requires full write iteration, breaks -n option
 *
 * b) keep FIDs and truncate them during the iteration
 *    PRO: no complete write iteration requires
 *    CON: deduplication becomes harder
 *    (OUR IMPLEMENTATION CHOICE!)
 *
 * c) already truncate during PREFILE generation
 *    PRO: easy to implement
 *    CON: cannot use PREFILE for both grouping and no grouping, breaks -n option
 *
 */

#define GROUP(fid, D) (use_grouping ? ((fid) % (LIST_OF_PRIMES[groupsize_exponent][D % num_primes])) : (fid))
