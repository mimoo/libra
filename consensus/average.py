import glob

def average(content):
    b = [int(x) for x in content]
    return int(sum(b) / len(b))


result = {}

for debug_file in glob.glob('./debug*'):
    res = 0
    with open(debug_file) as f:
        content = f.readlines()[1:]
        result[debug_file] = average(content)

for line, val in result.items():
    print(val, line[2:])


