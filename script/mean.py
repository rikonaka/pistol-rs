import json


def main():
    filename = 'mean.txt'
    ret = {}
    with open(filename, 'r') as fp:
        name = ''
        for l in fp.readlines():
            if '*' in l:
                name = l.replace('/*', '').replace('*/', '').strip()
            else:
                value = [x.strip().replace(
                    '{', '').replace('}', '') for x in l.split(',')]
                value = [float(x) for x in value if len(x) > 0]
                ret[name] = value

    # print(ret)
    output_filename = 'mean.json'
    with open(output_filename, 'w') as fp:
        json.dump(ret, fp)


main()
