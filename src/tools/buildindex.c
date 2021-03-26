#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdarg.h>
#include "util/qsort.h"
#include "util/uthash.h"
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "buildindex.h"
#include "util/primes.h"
#include <ctype.h> // for isprint()

/*
 * yarix-indexbuild.c
 *
 *
 * This tool creates a YarIx-compatible inverted index of malware files.
 * It does so using the following two-staged methodology:
 *
 *  (1) Read malware files one by one, and thereby create preliminary files
 *      (prefiles) that store per <AB> in the 4-gram <ABCD> a list of
 *      (<CD>, <file ID>) tuples (each 6 bytes).
 *
 *      --> build_stage_1() -> stage1_thread() -> process_file() -> sample_to_prefiles()
 *
 *  (2) Read prefiles, sort them, and store deduplicated posting list entries
 *      in the final index files. 256 prefiles (all <C>s in <ABCD>) are combined
 *      into a single index file for <ABC>. The index file starts with 256 offsets
 *      that point to the positions of the 256 <D>s' file IDs.
 *
 *      --> build_stage_2() -> converter_thread() -> convert_prefile()
 *
 *
 *
 *  NOTES:
 *  - The second stage alone will create about 2^24 ~= 16.7M files. Make sure
 *    you have sufficiently many free inodes in your file system (`df -i`)
 *
 *  - You can limit the number of files that should be indexed. Actually, it
 *    is advised doing so, as indexing very large input sets can take days
 *    and intermediate results are *not* stored. `merge` is a tool for combining
 *    index files into one joint index.
 *
 *  - The `NUM_STAGE2_WORKERS` constant heavily influences both memory
 *    usage and performance of this tool. Higher values will result in better
 *    performance, but will demand significantly more RAM. Please consult the
 *    the yarix-indexbuild.h header file for reasonable configurations.
 */


/** GLOBALS **/
/* in-memory representation of prefiles (<AB> -> (<CD>,fileID)) */
PLE PLs[256*256][MAX_IN_MEM_PL_SIZE];

/* points to next free element in `PLs` per <AB> */
uint16_t PL_offsets[256*256];

/* access to PL_offsets is not thread-safe, thus a lock */
pthread_mutex_t PL_locks[256*256];

/* general global lock for some critical areas */
pthread_mutex_t global_lock;

/* specifies which <AB> prefile to convert next */
size_t cur_prefix = 0;

/* globals for reading a list of malware files to index */
size_t next_fid = 0;                // file ID assigned to malware file processed next
char filenames[MAX_NUM_FILE_NAMES][MAX_FILENAME_LENGTH]; // array of 512B-long filenames
size_t filenames_offset = 0;        // offset of current file to process
size_t filenames_num = 0;           // total number of files that will be processed

/* time for progress monitor */
time_t checkpoint_time = 0;

/* path to write files to (specified with -w option) */
char *output_dir = NULL;

/* number of files to index (after which we abort) */
size_t num_files_to_index = MAX_NUM_FILE_NAMES;

char *input_file_list = NULL;

/* specifies whether or not input files are gzip compressed */
uint8_t use_gzip = 0;

/* file ID group-based compression settings */
uint8_t use_grouping = 0;
// see `gn_x` in paper
uint32_t groupsize_exponent = 0;

/* logging control (-d) */
uint8_t log_level_debug = 0;

/* keep prefiles (-k) */
uint8_t keep_prefiles = 0;

/* omit n-grams that include one or more zero bytes (-0) */
uint8_t omit_zero_bytes = 0;

/* append -g<n> to filename to indicate it's a grouped posting list */
char groupsuffix[1024] = { 0 };
uint32_t num_primes = 256;


/* basic stdout logging functions */
void log_format(const char* tag, const char* message, va_list args) {
    struct timeval t;
    gettimeofday(&t, NULL);
    printf("%ld.%06ld [%s] ", t.tv_sec, t.tv_usec, tag);
    vprintf(message, args);
}
void log_error(const char* message, ...) {  va_list args;   va_start(args, message);    log_format("error", message, args);     va_end(args); }
void log_info(const char* message, ...) {   va_list args;   va_start(args, message);    log_format("info", message, args);      va_end(args); }
void log_debug(const char* message, ...) { if (log_level_debug) { va_list args;   va_start(args, message);    log_format("debug", message, args);     va_end(args); } }



/* read uncompressed malware sample `fname` into `buffer` and store number
 * of bytes read in `size` */
void read_plainfile_into_buf(char *fname, char *buffer, size_t *size) {
    FILE *f = fopen(fname, "rb");
    if (!f) {
        log_error("reading %s failed: %s\n", fname, strerror(errno));
    }
    assert(f != NULL);
    size_t n = 0, i = 1;

    while (i) {
        i = fread(buffer+n, 1, *size - n, f);
        n += i;
    }
    *size = n;

    assert(!fclose(f));
}

/* read gziped malware sample `fname` into `buffer` and store number
 * of bytes read in `size` */
void read_gzipfile_into_buf(char *fname, char *buffer, size_t *size) {
    // from https://www.lemoda.net/c/gzfile-read/
    gzFile file;
    file = gzopen (fname, "r");
    if (!file) {
        fprintf (stderr, "gzopen of '%s' failed: %s.\n", fname, strerror (errno));
        exit (EXIT_FAILURE);
    }
    size_t size_total = 0;
    while (1) {
        int err;                    
        int bytes_read;
        bytes_read = gzread (file, buffer, *size - 1);
        assert(bytes_read >= 0);
        size_total += bytes_read;
        buffer[bytes_read] = '\0';
        if ((unsigned int) bytes_read < *size - 1) {
            if (gzeof (file)) {
                break;
            }
            else {
                const char * error_string;
                error_string = gzerror (file, & err);
                if (err) {
                    fprintf (stderr, "Error: %s.\n", error_string);
                    exit (EXIT_FAILURE);
                }
            }
        }
    }
    gzclose (file);
    *size = size_total;
}

/* Store number `n` in buffer `buf` using 7-bit variable-length encoding */ 
//size_t varbyte_enc(uint64_t n, uint8_t* buf) {
size_t varbyte_enc(uint32_t n, char *buf) {
    size_t num = 0;
    
    do {
        buf[num] = (uint8_t) (n & 0x7FU) | 0x80U;
        n >>= 7;
        num++;
    } while (n != 0);
    
    buf[num-1] &= 0x7FU;
    return num;
}


/* read a prefile for a given `ngram_prefix`, and convert it into
 * 256 <ABC> files containing all <D> posting lists each */
void convert_prefile(uint32_t ngram_prefix) {
    char fpath[BUFSIZ];
    FILE *f;
    size_t n, i, num_ple_in_prefile, filesz;
    uint32_t c, d;
    uint8_t firstiter = 1;
   
    // compute path of prefile and open it
    snprintf(fpath, BUFSIZ, "%s/%02x/%02x.prefile",
        output_dir,
        ngram_prefix >> 8,
        ngram_prefix & 0xFF);
    f = fopen(fpath, "rb");
    assert(f != NULL);

    // check if we have sufficient memory to read prefile
    fseek(f, 0L, SEEK_END);
    filesz = ftell(f); // read file size
    rewind(f);
    if (filesz > sizeof(PLE) * MAX_PLEs) {
        log_error("ERROR: file size %llu does not fit into max allocation. Increase `MAX_PLEs` and recompile. Aborting!\n", filesz);
        fclose(f);
        exit(-1);
    }

    // read prefile
    PLE *entries = malloc(sizeof(PLE) * MAX_PLEs); // 4G * 6B = 24 GB *per converter thread*
    if (entries == NULL) {
        log_error("ERROR: failed to acquire memory for `entries` variable. This likely means that your system has too little RAM. Try decreasing `MAX_PLEs` and `-n` accordingly. Aborting!\n");
        exit(-1);
    }
    
    num_ple_in_prefile = 0;
    while (num_ple_in_prefile < MAX_PLEs) {
        i = fread(entries+num_ple_in_prefile, sizeof(PLE), MAX_PLEs - num_ple_in_prefile, f);
        //log_info("read %'llu items of size %llu\n", i, sizeof(PLE));
        if (i == 0) {
            break;
        }
        num_ple_in_prefile += i;
    }
    
    assert(num_ple_in_prefile < MAX_PLEs); // check if we dropped some PLEs
    log_debug("read %'llu PLEs from %s\n", num_ple_in_prefile, fpath);
    
    assert(fclose(f) == 0);
    if (num_ple_in_prefile == 0) { goto exit_convert_prefile; }

    PL *pl = malloc(MAX_PL_SIZE);
    assert(pl != NULL);
    char *plbuf = (char *) pl;
    assert(pl != NULL);

    //log_info("qsort starting... tid=%d (n=%llu)\n", ngram_prefix % NUM_WORKERS, num_ple_in_prefile);
    // inlined QSORT for the sake of performance
    // see: https://github.com/svpv/qsort
    PLE tmp;
#define LESS(i, j)  entries[i].ngram_suffix < entries[j].ngram_suffix || (entries[i].ngram_suffix == entries[j].ngram_suffix && GROUP(entries[i].fid, get_D(i)) < GROUP(entries[j].fid, get_D(j)))
#define SWAP(i, j)  memcpy(&tmp, entries+i, sizeof(PLE)), \
                    memcpy(entries+i, entries+j, sizeof(PLE)), \
                    memcpy(entries+j, &tmp, sizeof(PLE))
    QSORT(num_ple_in_prefile, LESS, SWAP);
    //log_info("qsort done. tid=%d (n=%llu)\n", ngram_prefix % NUM_WORKERS, num_ple_in_prefile);

    i = 0;
    /* iterate over all <C>s, and for each <ABC>, create one file with 256 posting lists */
    for (c = 0; i < num_ple_in_prefile && c <= 0xFF; c++) {
        uint32_t last_fid = MAXUINT32;          // support max 2^32-1 files :-)
        size_t pl_size = sizeof(pl->offsets);   // offset of current PLE in PL; skip 256x 8B counters
        uint64_t *plcounter = NULL;
        firstiter = 1;

        /* offsets per ABCD are initially set to MAXINT, and only updated to the actual
         * correct offset if at least one file contains ABCD */
        memset(pl->offsets, 0xFF, sizeof(pl->offsets));

        /* start with the first D for the current C */
        d = get_D(i);

        //printf("have PLE suffix=%04x FID=%d\n", entries[i].ngram_suffix, entries[i].fid);
        while ((i < num_ple_in_prefile) && (get_C(i) == c)) {
            
            // check for change in 4th byte (<D>), and if so, update counters
            if (get_D(i) != d || firstiter) {
                assert(get_D(i) > d || firstiter);
                firstiter = 0;
                last_fid = MAXUINT32;
                
                d = get_D(i);
                
                /* store offset (overwrite MAXINT) */
                pl->offsets[d] = pl_size - sizeof(pl->offsets);

                /* update number of PLEs for current ABCD */
                plcounter = (uint64_t *) (plbuf + pl_size);
                *plcounter = 0;

                /* reserve 8B for plcounter variable at start of PLE for ABCD */
                pl_size += sizeof(uint64_t);
            }
            
            //log_debug("d=%d at i=%d (expected: %d)\n", d, i, entries[i].ngram_suffix & 0xFF);
            assert(pl_size >= sizeof(pl->offsets) + sizeof(uint64_t));
            assert(pl_size < MAX_PL_SIZE - BUFSIZ); // sufficient room to add an entry
            
            // deduplication (skip duplicate entries)
            uint32_t fid = GROUP(entries[i].fid, get_D(i));
            //log_debug("fid %d (D=%d) has become gid %d (use_grouping = %d, modulus = %d)\n",
            //    entries[i].fid, get_D(i), fid, use_grouping, LIST_OF_PRIMES[groupsize_exponent][get_D(i) % num_primes]);
            if (fid != last_fid) {
                size_t width;
                if (last_fid == MAXUINT32) {
                    // first fileID per ABCD list is stored as absolute 4B-wide number
                    width = sizeof(fid);
                    memcpy(plbuf + pl_size, &fid, sizeof(fid));
                    last_fid = fid;
                } else {
                    // all others use delta encoding
                    assert(last_fid < fid);
                    uint32_t tmp_fid = fid;
                    fid = tmp_fid - last_fid;
                    last_fid = tmp_fid;
                    width = varbyte_enc(fid, plbuf + pl_size);
                }
                
                // write delta (or absolute for first value)
                *plcounter = *plcounter + 1;
                pl_size += width;
            }

            i++; // process next PLE in prefile
        }
            
        if (pl_size != sizeof(pl->offsets)) {
            // dump non-empty posting list to file
            //log_debug("Dumping %d entries (offset = %d) to %s\n", num_ple_in_prefile, pl_size, fpath);
            snprintf(fpath, BUFSIZ, "%s/%02x/%02x/%02x.postlist%s",
                output_dir,
                ngram_prefix >> 8,
                ngram_prefix & 0xFF,
                c,
                groupsuffix);
            f = fopen(fpath, "wb");
            assert(f != NULL);
            
            n = fwrite(pl, 1, pl_size, f);
            assert(n == pl_size);
            
            fclose(f);
        }
    }

    assert(i == num_ple_in_prefile || i == num_ple_in_prefile + 1);

    free(pl);
    if (!keep_prefiles)
    {
        snprintf(fpath, BUFSIZ, "%s/%02x/%02x.prefile",
            output_dir,
            ngram_prefix >> 8,
            ngram_prefix & 0xFF);
        remove(fpath);
    }
exit_convert_prefile:
    free(entries);

}

void *converter_thread(__attribute__((unused)) void *td) {
    uint32_t next_prefix; // specifies <AB>, i.e., which prefile to convert

    while (1) {
        pthread_mutex_lock(&global_lock);
        next_prefix = cur_prefix;
        cur_prefix++;
        if (cur_prefix % CHECKPOINT_INTERVAL == 0) {
            time_t t = time(0);
            time_t diff = t - checkpoint_time;
            time_t fps;
            if (diff > 0) {
                fps = CHECKPOINT_INTERVAL / diff;
            } else {
                fps = 0;
            }
            log_info("Finished converting %d files, speed of %d fps\n", cur_prefix, fps);
            checkpoint_time = t;

        }
        pthread_mutex_unlock(&global_lock);
        if (next_prefix > 0xFFFF) {
            break;
        }
        convert_prefile(next_prefix);
    }
    
    return NULL;
}

void write_tmp_PLs_to_predefrag_files(uint32_t ngram_prefix) {
    char fpath[BUFSIZ];
    FILE *f;
    size_t n;
    
    snprintf(fpath, BUFSIZ, "%s/%02x/%02x.prefile",
        output_dir,
        ngram_prefix >> 8,
        ngram_prefix & 0xFF);
    f = fopen(fpath, "ab");
    if (!f) {
        log_error("writing %s failed: %s\n", fpath, strerror(errno));
    }
    assert(f != NULL);
    
    n = fwrite(PLs[ngram_prefix], sizeof(PLE), PL_offsets[ngram_prefix], f);
    //log_debug("dumped %d of %d PLEs to %s\n", n, PL_offsets[ngram_prefix], fpath);
    if (n != PL_offsets[ngram_prefix]) {
        fprintf(stderr, "expected %d, wrote %zu\n", PL_offsets[ngram_prefix], n);
        perror("write error\n");
        exit(EXIT_FAILURE);
    }

    n = fclose(f);
    assert(n == 0);
}
    

void *sample_to_prefiles(void *arg) {
    t_threaddata *td = (t_threaddata *) arg;
    char *buf = td->buf;
    uint32_t fid = td->fid;
    size_t size = td->size;
    size_t i;

    hash_ngram *known_ngrams = NULL;
    hash_ngram *hngram;

    for (i = 0; i <= size-4; i++) {
        uint32_t ngram = *((uint32_t *) (buf+i));
        ngram = ntohl(ngram);
        uint32_t ngram_prefix = ngram >> 16;
        uint32_t ngram_suffix = ngram & 0xFFFF;
        
        // split work by n-gram prefix to avoid any locking
        if ((ngram_prefix % NUM_NGRAM_WORKERS) != td->tid)
            continue;

        // skip over ngrams that contain a zero byte
        if (omit_zero_bytes && (!(ngram & 0xFF) || !(ngram & 0xFF00) || !(ngram & 0xFF0000) || !(ngram & 0xFF000000)))
            continue;

        // deduplicate ngrams; if we already had this ngram, ignore it
        // see: https://troydhanson.github.io/uthash/userguide.html
        HASH_FIND_INT(known_ngrams, &ngram, hngram);
        if (hngram != NULL) {
            //log_debug("skipping duplicate... %08x\n", ngram);
            continue;
        } else {
            //log_debug("new ngram %08x for file %d\n", ngram, fid);
            hngram = (hash_ngram *) malloc(sizeof(hash_ngram));
            assert(hngram != NULL);
            hngram->ngram = ngram;
            HASH_ADD_INT(known_ngrams, ngram, hngram);
        }
        
        pthread_mutex_lock(&PL_locks[ngram_prefix]);
        
        uint32_t offset = PL_offsets[ngram_prefix];
        if (offset >= MAX_IN_MEM_PL_SIZE) {
            write_tmp_PLs_to_predefrag_files(ngram_prefix);
            PL_offsets[ngram_prefix] = 0;
            offset = 0;
        }
        
        PL_offsets[ngram_prefix]++;

        assert(offset < MAX_IN_MEM_PL_SIZE);
        assert(ngram_prefix <= 0xFFFF);
        PLE *e = &(PLs[ngram_prefix][offset]);
        e->fid = fid;
        e->ngram_suffix = ngram_suffix;
        
        pthread_mutex_unlock(&PL_locks[ngram_prefix]);
    }

    hash_ngram *cur, *tmp;
    HASH_ITER(hh, known_ngrams, cur, tmp) {
        HASH_DEL(known_ngrams, cur);    /* delete; users advances to next */
        free(cur);                      /* optional- if you want to free  */
    }
    
    return NULL;
}


void process_file(char *fname, uint32_t fid) {
    uint64_t total_read_size = 0;
    size_t size = (size_t) MAX_INPUT_FILE_SIZE;
    size_t n;
    char *buf = (char *) malloc(size);
    assert(buf != NULL);
    log_debug("fid=%8d will read from %s\n", fid, fname);

    // read input file (plain or gziped), length in `size` afterwards
    if (use_gzip) {
        read_gzipfile_into_buf(fname, buf, &size);
    } else {
        read_plainfile_into_buf(fname, buf, &size);
    }
    
    assert(size < MAX_INPUT_FILE_SIZE); // abort, if input file too large

    // test if sufficiently long to build n-grams, otherwise ignore
    if (size < 4) goto abort_process_file;
    total_read_size += size;
    log_debug("fid=%8d read %d bytes from %s (total = %llu)\n", fid, size, fname, total_read_size);

    pthread_t workers[NUM_NGRAM_WORKERS];
    t_threaddata tdatas[NUM_NGRAM_WORKERS];
    memset(tdatas, 0, sizeof(tdatas));
    memset(workers, 0, sizeof(workers));

    for (n = 0; n < NUM_NGRAM_WORKERS; n++) {
        t_threaddata *t = &tdatas[n];
        t->tid = n;
        t->buf = buf;
        t->fid = fid;
        t->size = size;
        if (pthread_create(&workers[n], NULL, sample_to_prefiles, (void *) t)) {
            fprintf(stderr, "Error creating thread\n");
            exit(-1);
        }
    }

    for (n = 0; n < NUM_NGRAM_WORKERS; n++) {
        pthread_join(workers[n], NULL);
    }
    log_debug("fid=%8d done processing ngrams in %s\n", fid, fname);

abort_process_file:
    free(buf);
}

uint32_t next_ngram_prefix = 0;
void *flush_all_PLs_to_defrag_files(__attribute__((unused)) void *td) {
    uint32_t ngram_prefix;
    while (1) {
        pthread_mutex_lock(&global_lock);
        ngram_prefix = next_ngram_prefix;
        next_ngram_prefix++;
        pthread_mutex_unlock(&global_lock);
        
        if (ngram_prefix > 0xFFFF) {
            break;
        }

        write_tmp_PLs_to_predefrag_files(ngram_prefix);
    }
    
    return NULL;
}

void init_postinglist_directories() {
    char dirname[BUFSIZ];
    uint32_t first, second;

    for (first = 0; first < 256; first++) {
        snprintf(dirname, BUFSIZ, "%s/%02x", output_dir, first);
        mkdir(dirname, 0777);

        for (second = 0; second < 256; second++) {
            snprintf(dirname, BUFSIZ, "%s/%02x/%02x", output_dir, first, second);
            mkdir(dirname, 0777);
        }
        //log_debug("finished mkdir for 1=%02x and 2=%02x\n", first, second-1);
    }
}

void read_filenames() {
    char fpathsbuf[BUFSIZ];
    char *path = fpathsbuf;
    size_t cur_id = 0, n;
    FILE *fpaths;
    
    fpaths = fopen(input_file_list, "r");
    if (!fpaths) {
        log_error("reading %s failed: %s\n", input_file_list, strerror(errno));
    }
    assert(fpaths != NULL);
   
    /* use this to get a random (uncached) subset of files */
    //size_t i, to_skip;
    //srandom(time(NULL));
    //to_skip = (random() % 10000) + 97 * (random() % 1000); 
    //for (i = 0; i < to_skip; i++) {
    //    path = fgets(fpathsbuf, sizeof(fpathsbuf), fpaths);
    //}
    //log_info("skipped %d files\n", i);

    while (path != NULL && filenames_num < MAX_NUM_FILE_NAMES && filenames_num < num_files_to_index) {
        path = fgets(fpathsbuf, sizeof(fpathsbuf), fpaths);

        if (!path) break;
        for (n = strlen(path) - 1; isspace(path[n]); n--) {
            path[n] = '\0';
        }
        assert(n < MAX_FILENAME_LENGTH);
        strncpy(filenames[filenames_num], path, MAX_FILENAME_LENGTH);
        filenames_num++;

        cur_id++;
    }

    n = fclose(fpaths);
    assert(n == 0);

    if (filenames_num == MAX_NUM_FILE_NAMES) {
        log_info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        log_info("WARNING: had to truncate file name reading after %d entries.\n", MAX_NUM_FILE_NAMES);
        log_info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    } else { 
        log_info("read %d filenames\n", filenames_num);
        num_files_to_index = filenames_num;
    }
}


void *stage1_thread(__attribute__((unused)) void *td) {
    size_t cur_id = 0;
    while (1) {
        pthread_mutex_lock(&global_lock);
        cur_id = filenames_offset;
        filenames_offset++;
        if (cur_id % CHECKPOINT_INTERVAL == 0) {
            time_t t = time(0);
            time_t diff = t - checkpoint_time;
            time_t fps;
            if (diff > 0) {
                fps = CHECKPOINT_INTERVAL / diff;
            } else {
                fps = 0;
            }
            log_info("Finished converting %d files, speed of %d fps\n", cur_id, fps);
            checkpoint_time = t;

        }
        pthread_mutex_unlock(&global_lock);

        if (cur_id >= filenames_num) {
            break;
        }

        process_file(filenames[cur_id], cur_id);
    }

    return NULL;
}


void build_stage_1() {
    /*
     * writes 2^16 files to 2^16 files called
     *  `/nvme/cr-odb/A/B.ngrams.predefrag`
     * that each contain all 4-grams that start with AB.
     * specifically, write a list of PLE (2B ngram suffix, 4B fileID)
     *
     * the resulting files are partially sorted.
     * file IDs are sorted, yet 4-grams aren't.
     * there are duplicate PLE entries.
     */
    size_t n;
    pthread_t workers[NUM_READ_WORKERS] = { 0 };

    /* initialize offsets of next free PLE to zero */
    memset(PL_offsets, 0, sizeof(PL_offsets));

    /* read list of input files that need to be processed */
    read_filenames();
    
    log_info("read %d filenames, starting to process stage 1...\n", filenames_num);
   
    /* process malware files and store them in prefiles */
    for (n = 0; n < NUM_READ_WORKERS; n++) {
        if (pthread_create(&workers[n], NULL, stage1_thread, NULL)) {
            fprintf(stderr, "Error creating thread\n");
            exit(-1);
        }
    }
    
    for (n = 0; n < NUM_READ_WORKERS; n++) {
        log_debug("joining thread %d\n", n);
        pthread_join(workers[n], NULL);
    }
   
        
    log_info("will flush remaining content to disk (flush_all_PLs_to_defrag_files)\n");
    /* flush all PLs to disk (partially dumped already) */
    for (n = 0; n < NUM_READ_WORKERS; n++) {
        if (pthread_create(&workers[n], NULL, flush_all_PLs_to_defrag_files, NULL)) {
            fprintf(stderr, "Error creating thread\n");
            return;
        }
    }

    for (n = 0; n < NUM_READ_WORKERS; n++) {
        log_debug("joining thread %d\n", n);
        pthread_join(workers[n], NULL);
    }
}

void build_stage_2() {
    /*
     * read all 2^16 *.predefrag files and, for each, create a file called
     *  `/nvme/cr-odb/A/B/C.postlist`
     * that contains two things:
     *  1) 256 * 8B counter of FIDs per n-gram, and
     *  2) uncompressed and absolute FIDs
     */
    uint32_t n;
    pthread_t workers[NUM_STAGE2_WORKERS];
    uint32_t tnum[NUM_STAGE2_WORKERS];

    printf("entering stage 2\n");

    cur_prefix = 0x0;
    for (n = 0; n < NUM_STAGE2_WORKERS; n++) {
        tnum[n] = n;
        if (pthread_create(&workers[n], NULL, converter_thread, &tnum[n])) {
            fprintf(stderr, "Error creating thread\n");
            exit(-1);
        }
    }
    
    for (n = 0; n < NUM_STAGE2_WORKERS; n++) {
        log_debug("joining thread %d\n", n);
        pthread_join(workers[n], NULL);
    }
}

int main(int argc, char **argv) {
    int c;
    int do_init = 0, do_stage1 = 0, do_stage2 = 0;
    int do_all = 1;
   
    while ((c = getopt(argc, argv, "w:r:n:012izg:dk")) != -1)
    switch (c) {
        case '0':
            omit_zero_bytes = 1;
            break;
        case '1':
            do_all = 0;
            do_stage1 = 1;
            break;
        case '2':
            do_all = 0;
            do_stage2 = 1;
            break;
        case 'd':
            log_level_debug = 1; 
            break;
        case 'k':
            keep_prefiles = 1; 
            break;
        case 'i':
            do_all = 0;
            do_init = 1; 
            break;
        case 'n':
            num_files_to_index = strtol(optarg, (char **)NULL, 10);
            break;
        case 'r':
            input_file_list = optarg;
            break;
        case 'g':
            use_grouping = 1;
            groupsize_exponent = strtol(optarg, (char **)NULL, 10);
            // check for reasonable group numbers
            assert(groupsize_exponent >= 8);
            assert(groupsize_exponent <= 30);
            assert(LIST_OF_PRIMES[groupsize_exponent][0] > 0);
            for (num_primes = 0; LIST_OF_PRIMES[groupsize_exponent][num_primes] != 0; num_primes++) {}
            log_info("using grouping with exponent %d, using %d primes\n", groupsize_exponent, num_primes);
            snprintf(groupsuffix, sizeof(groupsuffix), "-g%d", groupsize_exponent);
            break;
        case 'z':
            use_gzip = 1;
            break;
        case 'w':
            output_dir = optarg;
            break;
        case '?':
            if (optopt == 'w' || optopt == 'r' || optopt == 'n')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            return -1;
        default:
            fprintf(stderr, "Aborting.\n");
            return -1;
    }

    /* check for required arguments */
    if (input_file_list == NULL) {
        fprintf(stderr, "You have to specify the input files (-r)\n");
        return -1;
    }

    if (output_dir == NULL) {
        fprintf(stderr, "You have to specify the output directory (-w)\n");
        return -1;
    }

    /* start da shit */
    log_info("STARTING importing up to %d files listed in %s\n", num_files_to_index, input_file_list);
    if (do_init || do_all) {
        log_info("INITING DIRS\n");
        init_postinglist_directories();
    }
    if (do_stage1 || do_all) {
        log_info("STARTING STAGE 1\n");
        build_stage_1();
    }
    if (do_stage2 || do_all) {
        log_info("STARTING STAGE 2\n");
        build_stage_2();
    }
    log_info("DONE importing %d files listed in %s\n", num_files_to_index, input_file_list);
    return 0;
}
