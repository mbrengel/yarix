#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "util/postinglistfile.h"

static volatile sig_atomic_t interrupted = 0;

static void sighandler(int _)
{
    (void)_;
    interrupted = 1;
}

int main(int argc, char *argv[])
{
    /* check cli args */
    if (argc < 8 || argc % 2 != 0)
    {
        fprintf(stderr, "usage: %s <offset> <limit> <targetpostingdir> <postingdir1> <size1> <postingdir2> <size2> [<postingdir3> <size3>...]\n", argv[0]);
        return -1;
    }
    size_t offset = atoi(argv[1]);
    size_t limit = atoi(argv[2]);

    /* compute shifts */
    size_t numpostingdirs = (argc - 4) / 2;
    int shifts[numpostingdirs];
    struct PLFile plfs[numpostingdirs];
    for (size_t i = 0; i < numpostingdirs; i++)
    {
        if (i > 0)
        {
            shifts[i] = shifts[i - 1] + atoi(argv[5 + i * 2]);
        }
        else
        {
            shifts[i] = atoi(argv[5 + i * 2]);
        }
    }

    /* install signal handler */
    signal(SIGINT, sighandler);

    /* start merging */
    uint8_t prefix[3];
    for (size_t i = offset; i < offset + limit && !interrupted; i++)
    {
        prefix[0] = (i >> 16) & 0xFF;
        prefix[1] = (i >> 8) & 0xFF;
        prefix[2] = i & 0xFF;
        char finalfilename[2048] = {0};
        char tmpfinalfilename[2048] = {0};
        sprintf(finalfilename, "%s/%02x/%02x/%02x.postlist_merged", argv[3], prefix[0], prefix[1], prefix[2]);
        sprintf(tmpfinalfilename, "%s/%02x/%02x/%02x.postlist_merged_tmp", argv[3], prefix[0], prefix[1], prefix[2]);

        /* ignore existing merged files */
        if (access(finalfilename, F_OK) == -1)
        {
            /* open pl files */
            for (size_t j = 0; j < numpostingdirs; j++)
            {
                char path[2048] = {0};
                sprintf(path, "%s/%02x/%02x/%02x.postlist", argv[4 + j * 2], prefix[0], prefix[1], prefix[2]);
                plfile_init(plfs + j, path);
            }

            /* create temporary merged file */
            FILE *ffinal = fopen(tmpfinalfilename, "w");

            /* skip header (will be written later) */
            fseek(ffinal, 256 * 8, SEEK_CUR);

            /* merge pls suffix by suffix */
            uint64_t finalploffsets[256] = {0};
            for (size_t suffix = 0; suffix < 256; suffix++)
            {
                /* and postingdir by postingdir */
                finalploffsets[suffix] = ftell(ffinal) - 256 * 8;
                uint64_t finalplsz = 0;
                uint64_t finalplcurrfid = 0;
                for (size_t j = 0; j < numpostingdirs; j++)
                {
                    /* determine file id shift */
                    uint64_t shift = 0;
                    if (j > 0)
                    {
                        shift = shifts[j - 1];
                    }

                    /* add file ids */
                    plfile_seek_to_pl(plfs + j, suffix);
                    if (plfile_pl_has_next(plfs + j))
                    {
                        /* copy first file id */
                        uint32_t fid = plfile_pl_get_next(plfs + j) + shift;
                        if (!finalplsz)
                        {
                            fseek(ffinal, 8, SEEK_CUR);
                            fwrite(&fid, 4, 1, ffinal);
                        }
                        else
                        {
                            uint64_t delta = fid - finalplcurrfid;
                            for (;;)
                            {
                                uint8_t b = delta & 0x7F;
                                delta >>= 7;
                                if (delta)
                                {
                                    b |= 0x80;
                                    fwrite(&b, 1, 1, ffinal);
                                }
                                else
                                {
                                    fwrite(&b, 1, 1, ffinal);
                                    break;
                                }
                            }
                        }
                        finalplsz += plfs[j].currplsz;
                        finalplcurrfid = fid;

                        /* copy encoded deltas */
                        uint8_t chunk[128];
                        ssize_t readbytes = fread(chunk, sizeof chunk, 1, plfs[j].f) * sizeof chunk;
                        ssize_t processedbytes = 0;
                        for (uint64_t k = 1; k < plfs[j].currplsz; k++)
                        {
                            uint32_t delta = 0;
                            uint8_t b = 0;
                            int k = 0;
                            do
                            {
                                // fread(&b, 1, 1, plfs[j].f);
                                // fwrite(&b, 1, 1, ffinal);
                                b = chunk[processedbytes++];
                                if (processedbytes == readbytes)
                                {
                                    fwrite(chunk, processedbytes, 1, ffinal);
                                    readbytes = fread(chunk, sizeof chunk, 1, plfs[j].f) * sizeof chunk;
                                    processedbytes = 0;
                                }
                                delta |= ((b & 0x7FU) << (k * 7));
                                k++;
                            } while (b & 0x80);
                            finalplcurrfid += delta;
                        }
                        fwrite(chunk, processedbytes, 1, ffinal);
                    }
                }

                /* write final pl size if necessary */
                if (finalplsz)
                {
                    uint64_t tmp = ftell(ffinal);
                    fseek(ffinal, finalploffsets[suffix] + 256 * 8, SEEK_SET);
                    fwrite(&finalplsz, 8, 1, ffinal);
                    fseek(ffinal, tmp, SEEK_SET);
                }
                else
                {
                    finalploffsets[suffix] = 0xFFFFFFFFFFFFFFFFULL;
                }
            }

            /* write final pl offsets */
            fseek(ffinal, 0, SEEK_SET);
            fwrite(finalploffsets, 8, 256, ffinal);
            fclose(ffinal);

            /* rename temporary merged file */
            rename(tmpfinalfilename, finalfilename);

            /* close pl files */
            for (size_t j = 0; j < numpostingdirs; j++)
            {
                plfile_close(plfs + j);
            }
        }

        /* print progress */
        size_t cnt = i - offset + 1;
        if (cnt % 100 == 0 || cnt == limit)
        {
            fprintf(stderr, "\r[+] %lu/%lu (%.2f%%)", cnt, limit, 100 * (double)cnt / limit);
            if (cnt == limit)
            {
                fprintf(stderr, "\n");
            }
        }
    }

    return 0;
}
