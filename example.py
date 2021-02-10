#!/usr/bin/env python3
import malindex
import yarautil
import yaramod

# instantiate index
idx = malindex.Index("data/idx", "samples.txt", 32321740, 0)

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
