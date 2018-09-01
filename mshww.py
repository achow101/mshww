#! /usr/bin/env python3

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from hwilib.commands import process_commands as hwi_command

import argparse
import sys
import json
import urllib
import binascii
import os

def enumerate(args):
    return hwi_command(['enumerate'])

def CreateWalletAndGetRPC(wallet_name, port, user, password):
    print("Making Core wallet")
    rpc = AuthServiceProxy("http://{}:{}@127.0.0.1:{}".format(user, password, port))
    rpc.createwallet(wallet_name)

    wallet_path = "/wallet/{}".format(urllib.parse.quote(wallet_name))
    return AuthServiceProxy("http://{}:{}@127.0.0.1:{}{}".format(user, password, port, wallet_path))

def LoadWalletAndGetRPC(wallet_name, port, user, password):
    print("Loading a Core wallet")
    rpc = AuthServiceProxy("http://{}:{}@127.0.0.1:{}".format(user, password, port))
    if wallet_name:
        wallets = rpc.listwallets()
        if wallet_name not in wallets:
            try:
                result = rpc.loadwallet(wallet_name)
            except:
                rpc.createwallet(wallet_name)
        
        wallet_path = "/wallet/{}".format(urllib.parse.quote(wallet_name))
        return AuthServiceProxy("http://{}:{}@127.0.0.1:{}{}".format(user, password, port, wallet_path))
    else:
        return rpc

def ProcessImportMultiString(importkeys):
    pubkeys = []
    for single_import in importkeys:
        pubkeys.append(single_import['pubkeys'][0])
    return pubkeys

def CreateWalletKeypool(args, wrpc, devices, internal):
    pubkeys = []
    for dtype, d in devices.items():
        if dtype == 'core':
            # Get the correct port
            if args.testnet:
                port = 18332
            elif args.regtest:
                port = 18443
            else:
                port = 8332
            rpc = LoadWalletAndGetRPC(d['wallet_name'], port, args.rpcuser, args.rpcpassword)
            
            # Get 1000 pubkeys
            core_pubkeys = []
            for i in range(0, 100):
                addrinfo = rpc.getaddressinfo(rpc.getnewaddress())
                info = {addrinfo['pubkey'] : {addrinfo['hdmasterkeyid'] :addrinfo['hdkeypath']}}

                core_pubkeys.append(info)
            pubkeys.append(core_pubkeys)
        else:
            print("Loading a {} wallet".format(dtype))
            # Common for all hww
            hwi_args = []
            if args.testnet or args.regtest:
                hwi_args.append('--testnet')
            hwi_args.append('-t')
            hwi_args.append(dtype)
            hwi_args.append('-d')
            hwi_args.append(d['device_path'])
            if 'password' in d:
                hwi_args.append('-p')
                hwi_args.append(d['password'])
            hwi_args.append('getkeypool')
            if internal:
                hwi_args.append('m/44h/0h/0h/1')
            else:
                hwi_args.append('m/44h/0h/0h/0')
            hwi_args.append('0')
            hwi_args.append('99')
            importkeys = hwi_command(hwi_args)

            pubkeys.append(ProcessImportMultiString(importkeys))

    print("Getting multisig keys")
    multisig_keys = []
    for i in range(0, 100):
        multisig_keys.append([])
    for pubkey_list in pubkeys:
        i = 0
        for pubkey in pubkey_list:
            multisig_keys[i].append(pubkey)
            i += 1

    print("Getting Multisig addresses")
    ms_addrs = []
    for keys in multisig_keys:
        cms_list = []
        for key in keys:
            [(pubkey, origin)] = key.items()
            cms_list.append(pubkey)
        ms = wrpc.createmultisig(args.n_sigs, cms_list)
        ms_addrs.append(ms['address'])

        # Make import multi object
        this_import = {}
        this_import['scriptPubKey'] = {'address' : ms['address']}
        this_import['redeemscript'] = ms['redeemScript']
        this_import['pubkeys'] = keys
        this_import['timestamp'] = 'now'
        this_import['keypool'] = True
        this_import['watch_only'] = True
        this_import['internal'] = internal
        wrpc.importmulti([this_import])

    return ms_addrs

def createwallet(args):
    devices = json.loads(args.devices)

    # Get the correct port
    if args.testnet:
        port = 18332
    elif args.regtest:
        port = 18443
    else:
        port = 8332

    # Generate the keypools
    wrpc = CreateWalletAndGetRPC(args.wallet, port, args.rpcuser, args.rpcpassword)
    external = CreateWalletKeypool(args, wrpc, devices, False)
    internal = CreateWalletKeypool(args, wrpc, devices, True)
    data = {}
    data['external_keypool'] = external
    data['internal_keypool'] = internal
    data['external_next'] = 0
    data['internal next'] = 0

    # Add the device info
    print("Getting device info")
    device_info = {}
    for dtype, d in devices.items():
        d_meta = {}
        if dtype == 'core':
            d_meta['wallet_name'] = d['wallet_name']
        else:
            # Common for all hww
            hwi_args = []
            if args.testnet or args.regtest:
                hwi_args.append('--testnet')
            hwi_args.append('-t')
            hwi_args.append(dtype)
            hwi_args.append('-d')
            hwi_args.append(d['device_path'])
            if 'password' in d:
                hwi_args.append('-p')
                hwi_args.append(d['password'])
            hwi_args.append('getmasterxpub')
            xpub = hwi_command(hwi_args)['xpub']

            d_meta['xpub'] = xpub
        device_info[dtype] = d_meta
    data['devices'] = device_info

    print("Writing wallet file")
    if not os.path.exists(os.path.expanduser("~/.mshww/")):
        os.makedirs(os.path.expanduser("~/.mshww/"))
    wallet_file = os.path.expanduser("~/.mshww/{}.json".format(args.wallet))
    with open(wallet_file, 'x') as f:
        json.dump(data, f, indent=2)

    return {'success' : True}

def newaddress(args):
    pass

def listused(args):
    pass

def send(args):
    pass

def process_commands(args):
    parser = argparse.ArgumentParser(description='Access and send commands to a hardware wallet device. Responses are in JSON format')
    parser.add_argument('--rpcuser', help='The username to the Bitcoin Core RPC interface')
    parser.add_argument('--rpcpassword', help='The password to the Bitcoin Core RPC interface')
    parser.add_argument('--testnet', help='Use testnet', action='store_true')
    parser.add_argument('--regtest', help='Use regtest', action='store_true')

    subparsers = parser.add_subparsers(description='Commands', dest='command')
    subparsers.required = True

    enumerate_parser = subparsers.add_parser('enumerate', help='List all available devices')
    enumerate_parser.set_defaults(func=enumerate)

    createwallet_parser = subparsers.add_parser('createwallet', help='Create a new wallet')
    createwallet_parser.add_argument('wallet', help='Name of the wallet')
    createwallet_parser.add_argument('devices', help='JSON format list of devices to use. One key from each device Ex: {"core":{"wallet_name":"hww"},"coldcard":{"device_path":"000:0001:00"}}')
    createwallet_parser.add_argument('n_sigs', type=int, help='Number signatures required')
    createwallet_parser.set_defaults(func=createwallet)

    newaddr_parser = subparsers.add_parser('getnewaddress', help='Gets the next address in the address pool')
    newaddr_parser.add_argument('wallet', help='Name of the wallet')
    newaddr_parser.add_argument('--label', help='A label for the address')
    newaddr_parser.set_defaults(func=newaddress)

    listused_parser = subparsers.add_parser('listused', help='List the addresses that have been used')
    listused_parser.add_argument('path', help='The BIP 32 derivation path to derive the key at')
    listused_parser.set_defaults(func=listused)

    signmsg_parser = subparsers.add_parser('send', help='Send Bitcoin to specified addresses')
    signmsg_parser.add_argument('recipients', help='The receiving addresses and their amounts as a JSON dictionary. See Bitcoin Core\'s sendmany for format')
    signmsg_parser.set_defaults(func=send)

    args = parser.parse_args(args)

    if args.testnet and args.regtest:
        return {'error' : "Cannot use both testnet and regtest"}

    # Do the commands
    return args.func(args)


if __name__ == '__main__':
    print(json.dumps(process_commands(sys.argv[1:])))
