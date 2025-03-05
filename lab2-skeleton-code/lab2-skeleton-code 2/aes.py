'''
# For more examples and documentation about the crypto library, see
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes

'''


import sys
import json
import logging
import argparse
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes



def encrypt(file, key, mode, outfile):

    logging.info('Encrypting...')

    with open(file, 'r') as fp:
        data = fp.read().encode()

    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC)
        data = pad(data, AES.block_size)

        ct_bytes = cipher.encrypt(data)
        iv_bytes = b64encode(cipher.iv)

        iv_str = iv_bytes.decode('utf-8')
        ct_str = b64encode(ct_bytes).decode('utf-8')

        data = {'iv': iv_str, 'ciphertext': ct_str}
    else:
        raise Exception('Not implemented')


    data_json = json.dumps(data)

    if outfile:
        with open(outfile, 'w') as fout:
            fout.write(data_json)
    else:
        print(data_json)


def decrypt(file, key, mode, outfile):
    raise Exception('Not implemented')



def check_key(key):
    '''
    Convert key from str to bytes.
    Check if it is 16 bytes long. If not, pad it using the pad() function as used in the encrypt() function above.
    If it is longer than 16 bytes, print an error and exit
    '''
    key = key.encode()
    if len(key) > 16:
        logging.error("Key should be up to 16 bytes long.")
        sys.exit(-1)
    if len(key) < 16:
        key = pad(key, AES.block_size)

    return key





def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypte with AES')

    parser.add_argument('--mode',
                        type=str,
                        default='CBC',
                        help='Specify mode. ECB, CBC, CTR. Default: CBC')
    parser.add_argument('--enc',
                        action='store_true',
                        help='Encrypt file')
    parser.add_argument('--dec',
                        action='store_true',
                        help='Decrypt file.')
    parser.add_argument('--key',
                        type=str,
                        required=True,
                        help='Encryption key.')
    parser.add_argument('-v',
                        action='count',
                        dest='verbose',
                        default=0,
                        help="Verbose level. -v, -vv")
    parser.add_argument('file',
                        type=str,
                        help='Input file')
    parser.add_argument('--out',
                        type=str,
                        help='Output file. If not given, print to terminal')

    args = parser.parse_args()

    log_levels = [logging.WARN, logging.INFO, logging.DEBUG]
    log_level = log_levels[min(args.verbose, 2)]
    log_format = '%(asctime)s.%(msecs)d %(name)s %(levelname)s %(message)s'
    logging.basicConfig(format=log_format,
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=log_level)


    key = check_key(args.key)

    if args.enc:
        encrypt(args.file, key, args.mode, args.out)
    elif args.dec:
        decrypt(args.file, key, args.mode, args.out)
    else:
        logging.error('Need either --enc or --dec arguments')



if __name__ == "__main__":
    main()
