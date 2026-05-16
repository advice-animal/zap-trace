import os
import sys
import threading

def do_work():
    while True:
        primes = [n for n in range(2, 10000) if not any(n%i == 0 for i in range(2, n))]

THREADS = []
for _ in range(4):
    t = threading.Thread(target=do_work, daemon=True)
    t.start()
    THREADS.append(t)

print("My PID is", os.getpid())
sys.stdin.readline()
print("Loading")
print(THREADS)

while True:
    print(sum(range(1_000_000)))

