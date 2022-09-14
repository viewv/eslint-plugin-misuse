with open("../data/top-1m.csv") as f:
    count = 0
    for line in f.readlines():
        print(line)
        count += 1

        if count > 20:
            break
