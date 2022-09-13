import os

path = os.getcwd()

with open("download_js/data/top-1m.csv") as f:
    count = 0
    for line in f.readlines():
        print(line)
        count += 1

        if count > 20:
            break
