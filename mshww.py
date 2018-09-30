#! /usr/bin/env python3

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from hwilib.commands import process_commands
from hwilib.serializations import PSBT
from hwilib.base58 import get_xpub_fingerprint_as_id
from bip32utils import BIP32Key

import argparse
import sys
import json
import urllib
import binascii
import os

def get_rpc_port(args):
    # Get the correct port
    if args.testnet:
        port = 18332
    elif args.regtest:
        port = 18443
    else:
        port = 8332
    return port

def load_wallet_file(wallet_name):
    # Load the wallet file
    wallet_file = os.path.expanduser("~/.mshww/{}.json".format(wallet_name))
    # Read the wallet file
    with open(wallet_file, 'r') as f:
        wallet = json.load(f)
    return wallet

def write_wallet_to_file(wallet_name, wallet):
    # Load the wallet file
    wallet_file = os.path.expanduser("~/.mshww/{}.json".format(wallet_name))
    # Write to the wallet
    with open(wallet_file, 'w') as f:
        wallet = json.dump(wallet, f, indent=2)

def get_addrtype(args, wallet):
    if 'addrtype' in args:
        return args.addrtype
    elif 'addrtype' in wallet:
        return wallet['addrtype']
    else:
        return 'p2sh-segwit'

def hwi_command(args):
    result = process_commands(args)
    if 'error' in result:
        raise ValueError(result['error'])
    return result

def enumerate(args):
    return hwi_command(['enumerate'])

def find_device_path(args, dtype, xpub, password = ''):
    devices = enumerate([])
    for device in devices:
        # Check devices with the same type
        if device['type'] == dtype:
            # Fetch the master xpub from the device
            hwi_args = []
            if args.testnet or args.regtest:
                hwi_args.append('--testnet')
            hwi_args.append('-t')
            hwi_args.append(device['type'])
            hwi_args.append('-d')
            hwi_args.append(device['path'])
            if password:
                hwi_args.append('-p')
                hwi_args.append(password)
            hwi_args.append('getmasterxpub')
            d_xpub = hwi_command(hwi_args)['xpub']

            # If the xpub matches, then we found our device
            if d_xpub == xpub:
                return device['path']
    return ''

def CreateWalletAndGetRPC(wallet_name, port, user, password):
    print("Making Core wallet")
    rpc = AuthServiceProxy("http://{}:{}@127.0.0.1:{}".format(user, password, port))
    rpc.createwallet(wallet_name, True)

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

def generate_keypool(args, wrpc, devices, start, end, internal, n_sigs, addrtype):
    pubkeys = []
    for dtype, d in devices.items():
        if dtype == 'core':
            rpc = LoadWalletAndGetRPC(d['wallet_name'], get_rpc_port(args), args.rpcuser, args.rpcpassword)
            
            # Get 1000 pubkeys
            core_pubkeys = []
            for i in range(start, end + 1):
                addrinfo = rpc.getaddressinfo(rpc.getnewaddress())
                info = {addrinfo['pubkey'] : {addrinfo['hdmasterkeyid'] :addrinfo['hdkeypath']}}

                core_pubkeys.append(info)
            pubkeys.append(core_pubkeys)
        elif 'xpub' in d and 'fingerprint' in d:
            print("xpub")
            parent = BIP32Key.fromExtendedKey(d['xpub'])
            if internal:
                parent = parent.ChildKey(1)
                path_base = 'm/44h/0h/0h/1/'
            else:
                parent = parent.ChildKey(0)
                path_base = 'm/44h/0h/0h/0/'

            import_pubkeys = []
            for i in range(start, end + 1):
                this_import = {}
                path = path_base + str(i)

                child = parent.ChildKey(i)
                address = child.Address()

                import_pubkeys.append({binascii.hexlify(child.PublicKey()).decode() : {d['fingerprint'] : path}})
            pubkeys.append(import_pubkeys)
        else:
            print("HWW")
            # Common for all hww
            hwi_args = []
            if args.testnet or args.regtest:
                hwi_args.append('--testnet')
            hwi_args.append('-f')
            hwi_args.append(d['fingerprint'])
            if 'password' in d:
                hwi_args.append('-p')
                hwi_args.append(d['password'])
            hwi_args.append('getkeypool')
            if internal:
                hwi_args.append('m/44h/0h/0h/1')
            else:
                hwi_args.append('m/44h/0h/0h/0')
            hwi_args.append(str(start))
            hwi_args.append(str(end))
            importkeys = hwi_command(hwi_args)

            pubkeys.append(ProcessImportMultiString(importkeys))

    print("Getting multisig keys")
    multisig_keys = []
    for i in range(start, end + 1):
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
        ms = wrpc.addmultisigaddress(n_sigs, cms_list, '', addrtype)
        ms_addrs.append(ms['address'])

        # Make import multi object
        this_import = {}
        this_import['scriptPubKey'] = {'address' : ms['address']}
        this_import['redeemscript'] = ms['redeemScript']
        this_import['pubkeys'] = keys
        this_import['timestamp'] = 'now'
        this_import['keypool'] = False
        this_import['watch_only'] = True
        this_import['internal'] = internal
        wrpc.importmulti([this_import])

    return ms_addrs

def createwallet(args):
    # Error if no rpc user and pass
    if not args.rpcuser or not args.rpcpassword:
        out = {'success' : False}
        out['error'] = '--rpcuser and --rpcpassword must be specified in order to create a new wallet'
        return out

    devices = json.loads(args.devices)

    # Generate the keypools
    wrpc = CreateWalletAndGetRPC(args.wallet, get_rpc_port(args), args.rpcuser, args.rpcpassword)
    external = generate_keypool(args, wrpc, devices, 0, 99, False, args.n_sigs, get_addrtype(args, {}))
    internal = generate_keypool(args, wrpc, devices, 0, 99, True, args.n_sigs, get_addrtype(args, {}))
    data = {}
    data['external_keypool'] = external
    data['internal_keypool'] = internal
    data['external_next'] = 0
    data['internal_next'] = 0

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
            hwi_args.append('-f')
            hwi_args.append(d['fingerprint'])
            if 'password' in d:
                hwi_args.append('-p')
                hwi_args.append(d['password'])
            xpub = hwi_command(hwi_args + ['getmasterxpub'])['xpub']

            d_meta['xpub'] = xpub
            d_meta['fingerprint'] = d['fingerprint']
        device_info.append(d_meta)
    data['devices'] = device_info
    data['nsigs'] = args.n_sigs
    data['addrtype'] = get_addrtype(args, {})

    print("Writing wallet file")
    if not os.path.exists(os.path.expanduser("~/.mshww/")):
        os.makedirs(os.path.expanduser("~/.mshww/"))
    wallet_file = os.path.expanduser("~/.mshww/{}.json".format(args.wallet))
    with open(wallet_file, 'x') as f:
        json.dump(data, f, indent=2)

    return {'success' : True}

def topupkeypool(args):
    # Error if no rpc user and pass
    if not args.rpcuser or not args.rpcpassword:
        out = {'success' : False}
        out['error'] = '--rpcuser and --rpcpassword must be specified in order to top up the keypool'
        return out

    # Load the watch only wallet
    rpc = LoadWalletAndGetRPC(args.wallet, get_rpc_port(args), args.rpcuser, args.rpcpassword)

    # Load the wallet file and get keypool info
    wallet = load_wallet_file(args.wallet)
    external_start = len(wallet['external_keypool'])
    internal_start = len(wallet['internal_keypool'])
    external_end = wallet['external_next'] + 100
    internal_end = wallet['internal_next'] + 100

    # Generate the keypools
    external_addrs = generate_keypool(args, rpc, wallet['devices'], external_start, external_end, False, wallet['nsigs'], get_addrtype(args, wallet))
    internal_addrs = generate_keypool(args, rpc, wallet['devices'], internal_start, internal_end, True, wallet['nsigs'], get_addrtype(args, wallet))
    wallet['external_keypool'] += external_addrs
    wallet['internal_keypool'] += internal_addrs

    # Write to the wallet
    write_wallet_to_file(args.wallet, wallet)
    return {'success' : True}

def newaddress(args):
    wallet = load_wallet_file(args.wallet)

    # Fetch the next address
    keypool = wallet['external_keypool']
    next_index = wallet['external_next']
    addr = keypool[next_index]

    # Increment the next address index
    wallet['external_next'] += 1

    # Write to the wallet
    write_wallet_to_file(args.wallet, wallet)

    out = {}
    out['addr'] = addr

    # Top up the keypool
    if args.notopup:
        topup_res = topupkeypool(args)
        if not topup_res['success']:
            out['warning'] = 'Failed to refill keypool: {}'.format(topup_res['error'])

    # Add the label to the wallet
    if args.label:
        if args.rpcpassword and args.rpcuser:
            rpc = LoadWalletAndGetRPC(args.wallet, get_rpc_port(args), args.rpcuser, args.rpcpassword)
            rpc.setlabel(addr, args.label)
        else:
            out['error'] = '--rpcuser and --rpcpassword necessary to set a label'

    return out

def listused(args):
    wallet = load_wallet_file(args.wallet)
    keypool = wallet['external_keypool']
    next_index = wallet['external_next']
    out = []
    for i in range(0, next_index):
        out.append(keypool[i])
    return out

def send(args):
    # Error if no rpc user and pass
    if not args.rpcuser or not args.rpcpassword:
        out = {'success' : False}
        out['error'] = '--rpcuser and --rpcpassword must be specified in order to top up the keypool'
        return out

    # Load the watch only wallet
    rpc = LoadWalletAndGetRPC(args.wallet, get_rpc_port(args), args.rpcuser, args.rpcpassword)

    # Load the wallet file
    wallet = load_wallet_file(args.wallet)

    # Get a change address from the internal keypool
    change_addr = wallet['internal_keypool'][wallet['internal_next']]
    wallet['internal_next'] += 1

    # Write to the wallet
    write_wallet_to_file(args.wallet, wallet)

    # Create the transaction
    outputs = json.loads(args.recipients)
    locktime = rpc.getblockcount()
    psbtx = rpc.walletcreatefundedpsbt([], outputs, locktime, {'changeAddress' : change_addr, 'replaceable' : True, 'includeWatching' : True}, True)
    psbt = psbtx['psbt']

    # HACK: Hack to prevent change detection because hardware wallets are apparently really bad at change detection for multisig change
    tx = PSBT()
    tx.deserialize(psbt)
    for output in tx.outputs:
        output.set_null()
    psbt = tx.serialize()

    # Send psbt to devices to sign
    out = {}
    psbts = []
    for dtype, d in wallet['devices'].items():
        if dtype == 'core':
            wrpc = LoadWalletAndGetRPC(d['wallet_name'], get_rpc_port(args), args.rpcuser, args.rpcpassword)
            result = wrpc.walletprocesspsbt(psbt)
            core_out = {'success' : True}
            out['core'] = core_out
            psbts.append(result['psbt'])
        else:
            d_out = {}

            hwi_args = []
            if args.testnet or args.regtest:
                hwi_args.append('--testnet')
            if 'password' in d:
                hwi_args.append('-p')
                hwi_args.append(d['password'])
            hwi_args.append('-f')
            hwi_args.append(d['fingerprint'])
            hwi_args.append('signtx')
            hwi_args.append(psbt)
            result = hwi_command(hwi_args)
            psbts.append(result['psbt'])
            d_out['fingerprint'] = d['fingerprint']
            d_out['success'] = True
            out[dtype] = d_out

    # Combine, finalize, and send psbts
    combined = rpc.combinepsbt(psbts)
    finalized = rpc.finalizepsbt(combined)
    if not finalized['complete']:
        out['success'] = False
        out['psbt'] = finalized['psbt']
        return out
    out['success'] = True
    if args.inspecttx:
        out['tx'] = finalized['hex']
    else:
        out['txid'] = rpc.sendrawtransaction(finalized['hex'])
    return out

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
    createwallet_parser.add_argument('--addrtype', choices=['legacy', 'p2sh-segwit', 'bech32'], help='The address types for the wallet. legacy is a p2sh multisig, p2sh-segwit is a p2wsh multisig wrapped in p2sh. bech32 is a p2wsh multisig')
    createwallet_parser.set_defaults(func=createwallet)

    newaddr_parser = subparsers.add_parser('getnewaddress', help='Gets the next address in the address pool')
    newaddr_parser.add_argument('wallet', help='Name of the wallet')
    newaddr_parser.add_argument('--label', help='A label for the address')
    newaddr_parser.add_argument('--notopup', help='Top up the keypool', action='store_false')
    newaddr_parser.set_defaults(func=newaddress)

    listused_parser = subparsers.add_parser('listused', help='List the addresses that have been used')
    listused_parser.add_argument('wallet', help='Name of the wallet')
    listused_parser.set_defaults(func=listused)

    send_parser = subparsers.add_parser('send', help='Send Bitcoin to specified addresses')
    send_parser.add_argument('wallet', help='Name of the wallet')
    send_parser.add_argument('recipients', help='The receiving addresses and their amounts as a JSON dictionary. See Bitcoin Core\'s sendmany for format')
    send_parser.add_argument('--inspecttx', help='Return the fully signed transaction instead of sending to inspect it prior to sending', action='store_true')
    send_parser.set_defaults(func=send)

    topup_parser = subparsers.add_parser('topupkeypool', help='Refills the pool of addresses so that there are 100 addresses available')
    topup_parser.add_argument('wallet', help='Name of the wallet')
    topup_parser.set_defaults(func=topupkeypool)

    args = parser.parse_args(args)

    if args.testnet and args.regtest:
        return {'error' : "Cannot use both testnet and regtest"}

    # Do the commands
    return args.func(args)


if __name__ == '__main__':
    print(json.dumps(process_commands(sys.argv[1:])))
