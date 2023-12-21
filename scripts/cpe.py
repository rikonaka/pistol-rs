import json


def main():
    filename = 'cpe.txt'
    result = []
    name_num = 0
    with open(filename, 'r') as fp:
        name = ''
        osclass_list = []
        cpe_list = []
        for l in fp.readlines():
            if 'match.OS_name' in l:
                if len(name) > 0:
                    tmp = {}
                    tmp['name'] = name
                    tmp['osclass'] = osclass_list
                    tmp['cpe'] = cpe_list
                    result.append(tmp)
                    osclass_list = []
                    cpe_list = []

                name_num += 1
                name = l.split('"')[-2]
                # print(name)
                
                # if name_num == 2:
                #     break

            elif 'OS_Classification osclass' in l:
                osclass_split = l.replace(',', '').split('"')
                osclass_split.pop(0)
                osclass_split.pop(-1)
                osclass = []
                for o in osclass_split:
                    if len(o.strip()) > 0:
                        osclass.append(o.strip())
                #print(osclass_list)
                osclass_list.append(osclass)
            elif 'osclass.cpe.push_back' in l:
                cpe_split = l.split('"')
                cpe = cpe_split[1]
                #print(cpe_list)
                cpe_list.append(cpe)
                # break

        tmp = {}
        tmp['name'] = name
        tmp['osclass'] = osclass_list
        tmp['cpe'] = cpe_list
        result.append(tmp)

    # print(ret)
    output_filename = 'cpe.json'
    with open(output_filename, 'w') as fp:
        json.dump(result, fp)


main()
