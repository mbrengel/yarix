#include <stdlib.h>
#include <stdint.h>
#include <Python.h>

#define NUM_FIDS 32321740

/* count for each file id how often we see it */
uint16_t *counts;

typedef struct {
    FILE* f;
    long int offset;
    uint64_t plsz;
} triple_t;

int compare_triple(const void* a, const void* b)
{
    triple_t *ta = (triple_t*)a;
    triple_t *tb = (triple_t*)b;

    if (ta->plsz < tb->plsz)
    {
        return -1;
    }
    else if (ta->plsz > tb->plsz)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

uint8_t Cmatch_posting_lists(const char* base, uint32_t* ngrams, uint32_t seqlen, uint32_t minmatches, uint32_t tar, PyObject* set)
{
    /* zero counts */
    memset(counts, 0, NUM_FIDS * 2);

    /* if it's a tar'ed posting directory, we first open the lookup file */
    FILE* flookup = NULL;
    if (tar)
    {
        char lookupfilename[512];
        sprintf(lookupfilename, "%s.lookup", base);
        flookup = fopen(lookupfilename, "r");
    }

    /* first, let's sort the posting lists by size */
    uint8_t ret = 0;
    triple_t triples[seqlen];
    uint32_t bestcase = 0;
    uint64_t prefixoffset = 0;
    for(uint32_t i = 0; i < seqlen; i++)
    {
        /* get current ngram */
        uint32_t ngram = ngrams[i];
        FILE* f;
        if (tar)
        {
            /* read offset from lookup file */
            fseek(flookup, 8 * (((ngram & 0xFF0000) >> 16) | (ngram & 0xFF00) | ((ngram & 0xFF) << 16)), SEEK_SET);
            fread(&prefixoffset, 8, 1, flookup);

            /* seek to correct position (if pl exists) */
            if (prefixoffset)
            {
                f = fopen(base, "r");
                fseek(f, prefixoffset, SEEK_SET);
            }
            else
            {
                f = NULL;
            }
        }
        else
        {
            /* create path */
            char path[1024];
            sprintf(path, "%s/%02x/%02x/%02x.postlist",
                base,
                (ngram & 0x000000FF),
                (ngram & 0x0000FF00) >> 8,
                (ngram & 0x00FF0000) >> 16);

            /* open file */
            f = fopen(path, "r");
        }

        if (f)
        {
            fseek(f, 8 * ((ngram & 0xFF000000) >> 24), SEEK_CUR);
            uint64_t o;
            fread(&o, 1, 8, f);

            /* keep track of size + offset for sorting and re-using later */
            if (o != 0xFFFFFFFFFFFFFFFFULL)
            {
                uint64_t plsz;
                bestcase++;
                fseek(f, prefixoffset + 256 * 8 + o, SEEK_SET);
                fread(&plsz, 8, 1, f);
                if (plsz)
                {
                    triples[i].f = f;
                    triples[i].offset = ftell(f);
                    triples[i].plsz = plsz;
                }
                else
                {
                    fclose(f);
                    triples[i].offset = -1;
                    triples[i].plsz = 0xFFFFFFFFFFFFFFFFULL;
                }
            }
            else
            {
                fclose(f);
                triples[i].offset = -1;
                triples[i].plsz = 0xFFFFFFFFFFFFFFFFULL;
            }
        }
        else
        {
            triples[i].offset = -1;
            triples[i].plsz = 0xFFFFFFFFFFFFFFFFULL;
        }
    }

    /* early exit */
    if (bestcase < minmatches)
    {
        ret = 0;
        goto bye;
    }

    /* sort by size */
    qsort(triples, seqlen, sizeof(triple_t), compare_triple);

    /* we keep track of the largest number of matches a file id had to allow for early exits */
    uint32_t maxseen = 0;

    for(uint32_t i = 0; i < seqlen && (maxseen + (seqlen - i) >= minmatches); i++)
    {
        /* get file + offset + posting list size */
        FILE* f = triples[i].f;
        long int o = triples[i].offset;
        uint64_t plsz = triples[i].plsz;

        /* if the posting list is not empty we continue */
        if (o != -1)
        {
            /* seek to where we left off */
            fseek(f, o, SEEK_SET);

            /* read first (absolute) file id */
            uint32_t fid;
            fread(&fid, 4, 1, f);

            /* keep track of counts and return set */
            if (++counts[fid] > maxseen)
            {
                maxseen = counts[fid];
            }
            if (counts[fid] == minmatches)
            {
                PyObject *pyfid = PyLong_FromLong(fid);
                if (!pyfid)
                {
                    ret = 1;
                    goto bye;
                }
                PySet_Add(set, pyfid);
                Py_DECREF(pyfid);
            }

            /* parse remaining file ids */
            for (uint64_t j = 0; j < plsz - 1; j++)
            {
                /* decode delta */
                uint32_t delta = 0;
                uint8_t b = 0;
                int k = 0;
                do {
                    fread(&b, 1, 1, f);
                    delta |= ((b & 0x7FU) << (k * 7));
                    k++;
                } while (b & 0x80U);

                /* compute current fid and keep track of counts and return set */
                fid += delta;
                if (++counts[fid] > maxseen)
                {
                    maxseen = counts[fid];
                }
                if (counts[fid] == minmatches)
                {
                    PyObject *pyfid = PyLong_FromLong(fid);
                    if (!pyfid)
                    {
                        ret = 1;
                        goto bye;
                    }
                    PySet_Add(set, pyfid);
                    Py_DECREF(pyfid);
                }
            }
        }
    }

bye:
    if (flookup)
    {
        fclose(flookup);
    }
    for(uint32_t i = 0; i < seqlen; i++)
    {
        if (triples[i].plsz != 0xFFFFFFFFFFFFFFFFULL)
            fclose(triples[i].f);
    }

    return ret;
}

static PyObject* match_posting_lists(PyObject* self, PyObject* args)
{
    /* parse arguments */
    PyObject* seq;
    uint32_t minmatches;
    const char* base;
    uint32_t tar;
    if (!PyArg_ParseTuple(args, "sOii", &base, &seq, &minmatches, &tar))
    {
        return Py_None;
    }

    /* convert python sequence to array */
    seq = PySequence_Fast(seq, "argument not iterable");
    if (!seq)
    {
        return Py_None;
    }
    uint32_t seqlen = PySequence_Fast_GET_SIZE(seq);
    uint32_t* ngrams = malloc(seqlen * 4);
    if (!ngrams)
    {
        Py_DECREF(seq);
        return Py_None;
    }
    for (uint32_t i = 0; i < seqlen; i++)
    {
        PyObject* item = PySequence_Fast_GET_ITEM(seq, i);
        if (!item)
        {
            Py_DECREF(seq);
            free(ngrams);
            return Py_None;
        }
        ngrams[i] = *(uint32_t*)PyBytes_AsString(item);
    }
    Py_DECREF(seq);

    /* initialize set */
    PyObject *set = PySet_New(NULL);
    if (!set)
    {
        free(ngrams);
        return Py_None;
    }

    /* call actual function */
    uint8_t res = Cmatch_posting_lists(base, ngrams, seqlen, minmatches, tar, set);
    free(ngrams);
    if (res == 1)
    {
        Py_DECREF(set);
        return Py_None;
    }

    return set;
}

static PyMethodDef methods[] = {
    { "match_posting_lists", match_posting_lists, METH_VARARGS, "" },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "malindexhelper",
    "",
    -1,
    methods
};

PyMODINIT_FUNC PyInit_malindexhelper(void)
{
    counts = malloc(NUM_FIDS * 2);

    return PyModule_Create(&module);
}
