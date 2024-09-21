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
    separator_symbol = '-'
    separator_len = 152
    seperator_line = ''.join([separator_symbol for i in range(separator_len)])
    print(seperator_line)
    print(f'{'NAME':35}| {'PRIVATE IP':17}| {'PUBLIC IP':17}| {'TX':17}| {'RX':17}| {'LATEST HANDSHAKE':40}')
    print(seperator_line)
    for val in data.values():
        print(f'{val['name']:35}| {val['private_ip']:17}| {val['public_ip']:17}| {val['TX']:>16} | {val['RX']:>16} | {val['latest_handshake']:>39}')
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
            conf_json[id]['latest_handshake'] = ' '.join(wg[i+2].split()[2::])
            
            temp_rx = wg[i+3].split()[1:3:]
            temp_tx = wg[i+3].split()[4:6:]
            if len(temp_rx) > 1:
                temp_rx[1] = temp_rx[1].replace('KiB', str(2**10)).replace('MiB', str(2**20)).replace('GiB', str(2**30)).replace('B', str(1))
                temp_tx[1] = temp_tx[1].replace('KiB', str(2**10)).replace('MiB', str(2**20)).replace('GiB', str(2**30)).replace('B', str(1))
            else:
                temp_rx[1] = 0.001
                temp_tx[1] = 0.001

            conf_json[id]['RX'] = f'{(float(temp_rx[0]) * float(temp_rx[1])) / MB:.2f} MiB'
            conf_json[id]['TX'] = f'{(float(temp_tx[0]) * float(temp_tx[1])) / MB:.2f} MiB'

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
