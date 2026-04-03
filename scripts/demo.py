from keke import kev
import sys
import time
import random
from threading import Thread


def do_work():
    time.sleep(random.random())
    while 1:
        with kev("summing"):
            sum(range(1_000_000))
        with kev("output"):
            sys.stderr.write(".")
            sys.stderr.flush()
        time.sleep(0.5)


threads = []

for _ in range(4):
    t = Thread(target=do_work, daemon=True)
    t.start()
    threads.append(t)

time.sleep(5)
