#!/usr/bin/env python3

#-------------------------------------------------------------------------------
# Name:        WG Analyze Tool
#
# Author:      Nikolay Sisyukin
# URL:         https://nikolay.sisyukin.ru/
#
# Created:     16.09.2024
# Copyright:   (c) Nikolay Sisyukin 2024
# Licence:     MIT License
#-------------------------------------------------------------------------------

GB = 2 ** 30  #  1GB in bytes
MB = 2 ** 20  #  1MB in bytes

import json, subprocess, sys, os, ipaddress

# ----------------------------------------------------------------------

def readJSONfromFile(filename):
    with open(filename, 'r', encoding='UTF-8') as f:
        return json.load(f)

# ----------------------------------------------------------------------

def dumpJSONtoFile(filename, data, mode='w'):
    if data != None:
        with open(filename, mode, encoding="UTF-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    return


def printTable(data):
    w_name = 34
    w_priv_ip = 16
    w_pub_ip = 16
    w_tr = 16
    w_time = 25
    separator_symbol = '-'
    separator_len = w_name + w_priv_ip + w_pub_ip + w_tr * 2 + w_time + 12
    seperator_line = ''.join([separator_symbol for i in range(separator_len)])
    print(seperator_line)
    print(f'{'NAME'.ljust(w_name)}| {'PRIVATE IP'.ljust(w_priv_ip)}| {'PUBLIC IP'.ljust(w_pub_ip)}| {'TX'.ljust(w_tr)} | {'RX'.ljust(w_tr)} | {'LATEST HANDSHAKE'.ljust(w_time)}')
    print(seperator_line)
    for val in data.values():
        print(f'{val['name'].ljust(w_name)}| {val['private_ip'].ljust(w_priv_ip)}| {val['public_ip'].ljust(w_pub_ip)}| ', end='')
        print(f'{val['TX'].rjust(w_tr)} | {val['RX'].rjust(w_tr)} | ', end='')
        print(f'{val['latest_handshake'].rjust(w_time)}')
    print(seperator_line)

# ----------------------------------------------------------------------

def analyze(conf_filename='/etc/wireguard/wg0.conf', show_table=True, sort_table_key='private_ip', show_json=True):
    conf = subprocess.run(['grep', '-i', 'peer', '-A3', conf_filename], capture_output=True, text=True).stdout.splitlines()
    wg = subprocess.run(['wg'], capture_output=True, text=True).stdout.splitlines()

    conf_json = {}
    for i, line in enumerate(conf):
        if 'peer' in line.lower():
            if '#' not in conf[i+2]:
                id = conf[i+3].split()[2].replace(',', '')
                conf_json[id] = {}
                conf_json[id]['name'] = conf[i+1].replace('#', '')
                conf_json[id]['key'] = conf[i+2].split()[2]
                conf_json[id]['private_ip'] = conf[i+3].split()[2].replace(',', '').split('/')[0]

    for i, line in enumerate(wg):
        if 'endpoint' in line.lower():
            id = wg[i+1].split()[2].replace(',', '')

            conf_json[id]['public_ip'] = wg[i].split()[1].split(':')[0]
            temp_handshake = []
            for word in wg[i+2].split()[2::]:
                if word.isdigit():
                    temp_handshake.append(f'{word.zfill(2)}')

                else:
                    temp_handshake.append(word)
            conf_json[id]['latest_handshake'] = ' '.join(temp_handshake)
            dict_for_replace = {' seconds':'s', ' second':'s',
                                ' minutes':'m', ' minute':'m',
                                ' hours':'h', ' hour':'h',
                                ' days':'d', ' day':'d'}
            for word in dict_for_replace.items():
                conf_json[id]['latest_handshake'] = conf_json[id]['latest_handshake'].replace(word[0], word[1])

            temp_rx = wg[i+3].split()[1:3:]
            temp_tx = wg[i+3].split()[4:6:]
            if len(temp_rx) > 1:
                temp_rx[1] = temp_rx[1].replace('KiB', str(2**10)).replace('MiB', str(2**20)).replace('GiB', str(2**30)).replace('B', str(1))
                temp_tx[1] = temp_tx[1].replace('KiB', str(2**10)).replace('MiB', str(2**20)).replace('GiB', str(2**30)).replace('B', str(1))
            else:
                temp_rx[1] = 0.001
                temp_tx[1] = 0.001

            conf_json[id]['RX'] = f'{((float(temp_rx[0]) * float(temp_rx[1])) / MB):,.2f} MiB'.replace(',', ' ')
            conf_json[id]['TX'] = f'{((float(temp_tx[0]) * float(temp_tx[1])) / MB):,.2f} MiB'.replace(',', ' ')

        if 'allowed' in line.lower() and 'endpoint' not in wg[i-1]:
            id = line.split()[2].replace(',', '')
            conf_json[id]['public_ip'] = ''
            conf_json[id]['latest_handshake'] = ''
            conf_json[id]['RX'] = ''
            conf_json[id]['TX'] = ''

    if show_json == True:
        print(json.dumps(conf_json, ensure_ascii='UTF-8', indent=4))

    conf_json_sort_by_private_ip = conf_json
    conf_json_sort_by_name = dict(sorted(conf_json.items(), key=lambda x: x[1].get('name')))

    if show_table == True:
        if sort_table_key == 'private_ip':
            printTable(conf_json_sort_by_private_ip)
        if sort_table_key == 'name':
            printTable(conf_json_sort_by_name)
# ----------------------------------------------------------------------

def main():
    #analyze(conf_filename='/etc/wireguard/wg0.conf', show_table=True, sort_table_key='private_ip', show_json=False)
    analyze(conf_filename='/etc/wireguard/wg0.conf', show_table=True, sort_table_key='name', show_json=False)

# ----------------------------------------------------------------------

if __name__ == '__main__':
    main()