#!/usr/bin/env python3
import sys
import subprocess
import os
import time
import threading

progress = {}

def worker(threadid, cmd):
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, universal_newlines=True)
    for line in p.stderr:
        line = line.rstrip("\n")
        if "%" in line:
            progress[threadid] = line[4:]
    p.wait()

if __name__ == "__main__":
    if len(sys.argv) < 7 or len(sys.argv) % 2 != 1:
        print("usage: merge.py <targetpostingdir> <numthreads> <postingdir1> <size1> <postingdir2> <size2> [<postingdir3> <size3>...]")
        sys.exit(-1)
    total = 1 << 24
    targetdir = sys.argv[1]
    numthreads = int(sys.argv[2])
    cnt = 0
    print("creating target directory structure")
    for a in range(256):
        for b in range(256):
            os.makedirs(os.path.join(targetdir, f"{a:02x}", f"{b:02x}"), exist_ok=True)
            cnt += 1
    dirs = []
    for i in range(int((len(sys.argv) - 3) / 2)):
        dirs.append((sys.argv[3 + i * 2], int(sys.argv[4 + i * 2])))
    step = int(total / numthreads)
    offset = 0
    print("starting merge")
    threads = []
    pobjs = []
    for i in range(numthreads):
        if i + 1 == numthreads:
            step = total - offset
        cmd = ["./src/tools/merge", str(offset), str(step), targetdir]
        offset += step
        for d, j in dirs:
            cmd += [d, str(j)]
        threads.append(threading.Thread(target=worker, args=(i, cmd)))
        progress[i] = ""
    for t in threads:
        t.start()
    while threading.active_count() > 1:
        os.system("clear")
        for i in range(numthreads):
            print(f"[Thread {i}]: {progress[i]}")
        time.sleep(1)
    os.system("clear")
    for i in range(numthreads):
        print(f"[Thread {i}]: {progress[i]}")
    print("renaming files")
    for folder, _, filenames in os.walk(targetdir):
        for filename in filenames:
            assert filename.endswith("_merged")
            path = os.path.join(folder, filename)
            newpath = os.path.join(folder, filename.rstrip("_merged"))
            os.rename(path, newpath)
