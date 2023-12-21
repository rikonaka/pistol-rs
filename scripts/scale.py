import json


def main():
    filename = 'scale.txt'
    result = []
    with open(filename, 'r') as fp:
        for l in fp.readlines():
            lsplit = [x.replace('{', '')
                      .replace('}', '')
                      .replace('/*', '')
                      .replace('*/', '')
                      .strip() for x in l.split(',')]
            a = float(lsplit[0])
            b = float(lsplit[1])
            name = lsplit[2]
            tmp = {}
            tmp['name'] = name
            tmp['value'] = [a, b]
            result.append(tmp)

    output_filename = 'scale.json'
    with open(output_filename, 'w') as fp:
        json.dump(result, fp)


main()
