# YarIx
This repository contains the code for the paper: "YarIx: Scalable YARA-based Malware Intelligence".

# Preparation
To build YarIx and install its dependencies on a Debian machine, simply run the following instructions in the top directory of this repository:
```
apt-get install cmake curl flex bison g++ gcc make python3 python3-dev python3-venv zlib1g zlib1g-dev wget
python3 -m venv YarIx
source YarIx/bin/activate
python3 -m pip install pip==21.0.1
make -C src/
pip install -r requirements.txt
```
For a different linux distribution you probably need to adapt the first line to your package manager and environment.
The instructions above create a virtual python environment called `YarIx` that needs to be activated as demonstrated so that `YarIx` can be used.

# Overview
After the previous step, the top directory should contain the following files and directories:

- `src/`: Source code for the index build and merge tools as well as the python extension
- `buildindex`: The index build utility
- `merge.py`: Frontend python script for merging indexes
- `malindex.py`: Python module for querying indexes
- `malindexhelper.so`: Python extension for boosting `malindex.py`
- `yarautil.py`: Python module for querying an index with YARA rules
- `example.py`: Example code demonstrating how to use YarIx
- `README.md`: This README

# Quick Start
## Create an Index
Assum you have a file called `samples1.txt` consisting of 100k lines with each line being the path of a malware sample.
To build an index into the direcotry `idx1` you  run:
```
mkdir idx1
./buildindex -r samples1.txt -w idx1
```

## Merge Two Indexes
Assume you did the same for a file `samples2.txt` and a directory `idx2` for another additional 100k samples.
To merge both indexes into a directory called `idx3`  run:
```
./merge.py idx3 24 idx1 100000 idx2 100000
```

## Using YarIx
To use the YARA scanning capabilities of YarIx, see `example.py`:
```
#!/usr/bin/env python3
import malindex
import yarautil
import yaramod

# instantiate index
idx = malindex.Index("data/idx", "samples.txt")

# search for ngram
ngram = b"pwnd"
fids = idx.get_posting_list(ngram)
print(f"There are {len(fids)} files containing the string '{ngram.decode()}'")

# parse rules
yararules = {rule.name: rule for rule in yaramod.parse_file("rules.yar").rules}

# extract rule
rulename = "win_carberp_auto"
rule = yararules[rulename]

# evaluate rule
fids = yarautil.evaluate_rule(rule, idx)
paths = [idx.fid2path(fid) for fid in fids]
print("There are {} files potentially matching {}".format(len(paths), rulename))

# get real matches
matches = set(yarautil.seqyarascan(paths, rule))
print("There are {} files definitively matching {}".format(len(matches), rulename))
for p in matches:
    print(p)
```

Executed on the full 32M dataset used in the paper, this yields:
```
There are 21768 files containing the string 'pwnd'
There are 57 files potentially matching win_carberp_auto
There are 30 files definitively matching win_carberp_auto
data/samples/6/0/0/600a95ad4686e69e10531652a20de60c
data/samples/7/3/e/73e78876d55b20104852af9ebd34c8c6
data/samples/2/5/6/25628a3536cf6d524a419189896907e9
data/samples/5/d/9/5d9535c9bfaf92bb7e9303469539f768
data/samples/f/1/b/f1bbda6b295286b5f7cd2e96cfe8c0f7
data/samples/9/8/4/984e46725e540fc02d86a1d953e80aa9
data/samples/0/a/b/0ab479694c3dba9a09b0d82316694635
data/samples/9/3/5/9354eddac31c6fe6419af0577fcb17fc
data/samples/7/4/d/74da65cf7c6e9a24488ed8447e892c26
data/samples/b/3/4/b3496a0d33b2d4d882fcbb3e7e785ee0
data/samples/6/a/3/6a313d1fd0e78ef41e0a7479afa04c22
data/samples/4/e/2/4e24c8a3dfdacac77bf4c5f1d4a1a391
data/samples/a/d/1/ad19c5d4a5584bd6d5d7147325bf8acb
data/samples/9/d/5/9d51df6befe90815caa476accbf7b23c
data/samples/4/1/3/41355682c2286c90d547c679e2125b0d
data/samples/f/9/c/f9ca0aed21dfa7bc1c463ae706e85dc3
data/samples/c/b/f/cbfcdaf2c59feb3bf551fea040cca300
data/samples/5/9/3/5933502cfb07d79a129eeffb54ce65ca
data/samples/0/2/1/02130bb3d24d458e99758847ccb8b785
data/samples/5/d/1/5d10153a7b415644af15788b950bcc82
data/samples/b/c/2/bc2f2c44f12ffd6df3dc2685980361e8
data/samples/7/d/0/7d06b3e5977776a4170926cca1c41d67
data/samples/f/6/4/f6438cdd68421ab38a659de75bdc0ffa
data/samples/0/9/b/09bae15bca57f6002431ba7ce0d12c81
data/samples/9/2/6/926320acc4660c9ab83c2190b62eb1f6
data/samples/3/5/c/35c4a1af123e41113e874b4559700b58
data/samples/f/0/6/f065c88cadae19ef9529ecb39586d35f
data/samples/1/4/b/14bd677dbc9c2876b07fca9c10ba9060
data/samples/d/0/b/d0b4ad7f92c09efad0185416d6d04df3
data/samples/9/e/6/9e680c8c3a76d1f035668cd457fd43ed
```

# Details
## Index Build Utility
*buildindex* accepts a list of files, from each of which it will read all 4-grams in order to create an inverted file index. It does so using the following two-staged methodology:

 (1) Read malware files one by one, and thereby create preliminary files
     (prefiles) that store per `<AB>` in the 4-gram `<ABCD>` a list of
     (`<CD>`, `<file ID>`) tuples (each 6 bytes).

 (2) Read prefiles, sort them, and store deduplicated posting list entries
     in the final index files. 256 prefiles (all `<C>`s in `<ABCD>`) are combined
     into a single index file for `<ABC>`. The index file starts with 256 offsets
     that point to the positions of the 256 `<D>`s' file IDs.

This tool has been tested on Linux only, and only on systems with sufficient RAM. Dynamic memory allocations are guarded by asserts, and if they fail, it's a sign that the system has too little RAM. We recommend >= 128GB RAM.

### Usage
`buildindex -r <file with list of input files> -w <output directory> -n <number of files to index> [more optional arguments]`

Required arguments:
- `-r`: Path to file that lists input files line by line.
- `-w`: Output directory where buildindex will create its output files to. The speed of this output directory is usually the bottleneck for the entire computation, i.e., choose your target wisely. Experiments with NVMe SSD cards have been very promising performance-wise. **WARNING**: buildindex will create approximately 2**24 ~= 17M files and subdirectories in this path. Make sure that you have sufficicly many i-nodes left.
- `-n`: Maximum number of files that should be indexed. The default and current maximum is 1M files. If you plan to index more files, it is highly advised to partition your input files into multiple 1M sets and merge the indexes using *yarix-indexmerge*. The main reason for this limit is the amount of memory that `buildindex` would otherwise require.

Optional arguments:

- `-0`: Skip n-grams that contain one or more zero bytes (*non-sound* optimization).
- `-1`: Only create prefiles, i.e., complete stage 1.
- `-2`: Only convert prefiles to create index files (while preserving the prefiles), i.e., complete stage 2.
- `-i`: Only init subdirectories in target directory, then exit. This is typically not required. Subdirectory creation is implicitly enabled if not called with options -1 or -2.
- `-d`: Enable debug logging.
- `-g [grouping-exponent]`: Enable group-based compression. This option is usually not recommend to use if sufficient disk space is available, as it slows down search performance, while reducing the disk footprint of the index. The core idea of this feature is to map the 32-bit-wide file IDs to shorter group IDs, i.e., join different FIDs in a shared GID. `grouping-exponent` is the exponent to the power of 2 and determines the number of groups, e.g., an exponent of 24 will create 2^24 groups.
- `-z`: Interpret all inputs files as gzip compressed instead of plaintext. Default input format is plaintext.

## Merge Tool
The YarIx merge tool consists of two components:

1. A backend tool `merge` with the following usage string: `usage: ./merge <offset> <limit> <targetpostingdir> <postingdir1> <size1> <postingdir2> <size2> [<postingdir3> <size3>...]`. A `postingdir`/`size` pair needs to be supplied for every index directory that needs to be merged where `postingdir` is the path to the index and `size` is the number of samples that are indexed by this index.
The file IDs of the posting directories will be shifted in the final index depending on their position in the argument list. For example if we assume all posint directories contain 100 file IDs, then the file IDs of `postingdir1` will be unmodified before being added to the final index. The file IDs of `postingdir2` will be shifted by 100, the IDs of `postingdir3` by 200 and so on. The path of the new index needs to be supplied in the `postingdir` argument. The tool will merge the individual `a/b/c.postlist` files of all supplied posting directories. It will skip the first `offset` files and merge `limit` of those files in total.
2. The frontend is a script `merge.py` that will use the backend `merge`. In particular, it will spawn multiple instances of `merge` and set the `limit` and `offset` accordingly to properly parallelize the operation. The usage string of the script is as follows: `usage: merge.py <targetpostingdir> <numthreads> <postingdir1> <size1> <postingdir2> <size2> [<postingdir3> <size3>...]`. It will spawn `numthreads` instances of the backend `merge`. The path `targetpostingdir` does not need to exist, it will be created by the frontend (including the `a/b` directory structure)

## Notes
- There is little reason to use the backend directly, stick to the frontend script
- The backend is designed to be re-runnable. For every prefix file `a/b/c.postlist` it will first create and merge the files into a file called `a/b/c.postlist_merged_tmp` and only once the merge is completed for this prefix it will rename the file to `a/b/c.postlist_merged`. Once the whole operation has completed, i.e., all prefixes are merged, the python script `merge.py` will rename the files to `a/b/c.postlist`. If something fails and the merge aborts, a subsequent run of the merge tool will skip a prefix if there is an existing `a/b/c.postlist_merged` file.
- `targetpostingdir` can be identical to one of the `postingdir1..n` arguments, i.e., instead of creating a new directory structure for an index, we then merge into an existing directory structure.
- Performance does **not** scale linearly with the number of indexed samples, i.e., it is only slightly slower to merge two 500k indexes than merging two 100k indexes.
