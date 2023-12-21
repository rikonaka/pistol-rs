import json


def main():
    filename = 'w.txt'
    result = []
    sum = 0
    with open(filename, 'r') as fp:
        name = ''
        for l in fp.readlines():
            if '*' in l:
                name = l.replace('/*', '').replace('*/', '').strip()
            else:
                value = [x.strip().replace(
                    '{', '').replace('}', '') for x in l.split(',')]
                value = [float(x) for x in value if len(x) > 0]
                sum += len(value)
                tmp = {}
                tmp['name'] = name
                tmp['value'] = value
                result.append(tmp)

    # print(ret)
    print(sum)
    output_filename = 'w.json'
    with open(output_filename, 'w') as fp:
        json.dump(result, fp)


main()
