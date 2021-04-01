#!/usr/bin/env python3

import gzip
import math
import os
import struct
import malindexhelper
import concurrent.futures

def is_prime(n):
    if n % 2 == 0 and n > 2:
        return False
    return all(n % i for i in range(3, int(math.sqrt(n)) + 1, 2))
primes = {}
for groupwidth in range(11, 23):
    p = (1 << groupwidth) - 1
    primes[groupwidth] = []
    while p >= 2 and len(primes[groupwidth]) < 256:
        if is_prime(p):
            primes[groupwidth].append(p)
        p -= 1
    primes[groupwidth] = sorted(primes[groupwidth])

class Index():
    def __init__(self, indexdir, pathlistfile, numsamples=None, is_tar=0):
        self.indexdir = indexdir
        self.pathlistfile = pathlistfile
        self.paths = []
        self.numsamples = numsamples
        self.is_tar = is_tar

    def get_file_path(self, prefix):
        a, b, c = map(str, map(str, prefix))
        return os.path.join(self.indexdir, a, b, c)

    @staticmethod
    def vlq_decode(f):
        curr = 0
        i = 0
        while True:
            c = f.read(1)
            if not c:
                break
            curr |= (ord(c) & 0x7F) << (7 * i)
            i += 1
            if ord(c) & 0x80 == 0:
                yield curr
                curr = 0
                i = 0

    def get_posting_list_old(self, ngram):
        if not isinstance(ngram, bytes):
            ngram = ngram.encode()
        assert len(ngram) >= 4
        if len(ngram) == 4:
            filepath = self.get_file_path(ngram[:3])
            with open(filepath, "rb") as f:
                f.seek(ngram[3] * 8)
                o = struct.unpack("<Q", f.read(8))[0]
                if o != 0xFFFFFFFFFFFFFFFF:
                    f.seek(256 * 8 + o)
                    l = struct.unpack("<Q", f.read(8))[0]
                    curr = struct.unpack("<I", f.read(4))[0]
                    yield curr
                    if l > 1:
                        for i, delta in enumerate(Index.vlq_decode(f)):
                            curr += delta
                            yield curr
                            if i+1 == l-1:
                                break
        else:
            m = {}
            ngrams = {ngram[i:i+4] for i in range(len(ngram) - 3)}
            for i, x in enumerate(sorted(ngrams, key=self.get_posting_list_size)):
                for fid in self.get_posting_list_old(x):
                    if i == 0 or fid in m:
                        if fid not in m:
                            m[fid] = 1
                        else:
                            m[fid] += 1
                        if i + 1 == m[fid] == len(ngrams):
                            yield fid


    def match_posting_lists(self, ngrams, minmatches):
        return malindexhelper.match_posting_lists(self.indexdir, ngrams, minmatches, self.is_tar)


    def get_posting_list_n3(self, ngrams):
        if isinstance(ngrams, str):
            ngrams = ngrams.encode()
        if isinstance(ngrams, bytes):
            ngrams = {ngrams[i:i+3] for i in range(len(ngrams) - 2)}
        intersection = None
        for x in ngrams:
            tmp = set.union(*[self.get_posting_list(x + bytes([i])) for i in range(256)])
            if intersection is None:
                intersection = tmp
            else:
                intersection &= tmp
            if not len(intersection):
                break
        return intersection


    def get_posting_list(self, ngrams, groupwidth=None, tau=None):
        if isinstance(ngrams, str):
            ngrams = ngrams.encode()
        if isinstance(ngrams, bytes):
            ngrams = {ngrams[i:i+4] for i in range(len(ngrams)-3)}
        assert len(ngrams) <= (1 << 16)

        if groupwidth is not None:
            # compute groups
            groups = {}
            prefilter = None
            for x in ngrams:
                p = primes[groupwidth][x[3]]
                pl = self.match_posting_lists({x}, 1)
                if tau is None or len(pl) <= tau:
                    groups[x] = {f % p for f in pl}
                else:
                    if prefilter is None:
                        prefilter = pl
                    else:
                        prefilter &= pl

            # compute intersection
            if len(groups) == 0:
                return prefilter
            minx, ming = min(groups.items(), key=lambda x: len(x[1]))
            p = primes[groupwidth][minx[3]]
            intersection = set()
            while len(ming) > 0:
                gid = ming.pop()
                if prefilter is None or gid in prefilter:
                    for y in groups:
                        if minx != y:
                            if gid % primes[groupwidth][y[3]] not in groups[y]:
                                break
                    else:
                        intersection.add(gid)
                gid += p
                if gid < self.numsamples:
                    ming.add(gid)
            return intersection
        return self.match_posting_lists(ngrams, len(ngrams))


    def get_posting_list_size(self, ngram):
        raise Exception("DON'T USE")
        # if not isinstance(ngram, bytes):
            # ngram = ngram.encode()
        # assert len(ngram) == 4
        # filepath = self.get_file_path(ngram[:3])
        # with open(filepath, "rb") as f:
            # f.seek(ngram[3] * 8)
            # o = struct.unpack("<Q", f.read(8))[0]
            # if o == 0xFFFFFFFFFFFFFFFF:
                # return 0
            # else:
                # f.seek(256 * 8 + o)
                # return struct.unpack("<Q", f.read(8))[0]

    def fid2path(self, fid):
        if self.numsamples is None or fid < self.numsamples:
            if not self.paths:
                with open(self.pathlistfile,  "rb") as f:
                    for i, l in enumerate(f):
                        if self.numsamples is None or i < self.numsamples:
                            self.paths.append(l.decode().rstrip())
            return self.paths[fid]

class MergedIndex():
    def __init__(self, indexdirs, numsamples, pathlistfile, is_tar):
        self.idxs = []
        offset = 0
        for id, ns in zip(indexdirs, numsamples):
            self.idxs.append((offset, Index(id, None, ns, is_tar)))
            offset += ns
        self.pathlistfile = pathlistfile
        self.paths = []
    
    def get_posting_list(self, ngrams, groupwidth=None, tau=None):
        def worker(offset, idx):
            return {x + offset for x in idx.get_posting_list(ngrams)}
        ret = set()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for offset, idx in self.idxs:
                futures.append(executor.submit(worker, offset, idx))
            for fut in concurrent.futures.as_completed(futures):
                ret |= fut.result()
        return ret
    
    def fid2path(self, fid):
        if not self.paths:
            with open(self.pathlistfile, "rb") as f:
                for l in f:
                    self.paths.append(l.decode().rstrip())
        return self.paths[fid]
