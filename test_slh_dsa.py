#!/usr/bin/env python3
"""Host-side timing for SLH-DSA signing over the Jade serial API.

This is the same measurement shape as the published 52.85 s figure: wall clock
around the RPC, so it includes the serial round trip and the on-device progress
bar redraws.  The 7856-byte signature reply at 115200 baud is about 0.7 s of
that.  For a number that isolates the primitive, build with CONFIG_JADE_SLH_BENCH
and read the on-device report instead.

    python3 test_slh_dsa.py [--device /dev/ttyACM0] [--iterations 5]
                            [--reduced] [--keygen]

The device must be unlocked (PIN entered) first.
"""

import argparse
import statistics
import time

from jadepy.jade import JadeAPI


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default='/dev/ttyACM0')
    ap.add_argument('--iterations', type=int, default=5)
    ap.add_argument('--reduced', action='store_true',
                    help="use Jade's reduced parameter set instead of SLH-DSA-SHA2-128s")
    ap.add_argument('--keygen', action='store_true', help='time KeyGen instead of SigGen')
    ap.add_argument('--network', default='mainnet')
    ap.add_argument('--temporary-wallet', action='store_true',
                    help='unlock with an in-memory test wallet (needs a --debug build); '
                         'nothing is written to the device')
    args = ap.parse_args()

    is_standard = not args.reduced
    label = 'KeyGen' if args.keygen else 'SigGen'
    param_set = 'SLH-DSA-SHA2-128s' if is_standard else 'custom-slh-dsa (h=45 d=5 a=13 k=10)'

    jade = JadeAPI.create_serial(device=args.device, timeout=600)
    jade.connect()

    if args.temporary_wallet:
        jade.set_mnemonic('all all all all all all all all all all all all',
                          temporary_wallet=True)
    else:
        print('Unlock the device (enter the PIN) to continue...')
        jade.auth_user(args.network)

    print(f'{label}, {param_set}, {args.iterations} iterations')
    times = []
    for i in range(args.iterations):
        seed = i.to_bytes(32, 'big')
        t0 = time.perf_counter()
        if args.keygen:
            reply = jade.gen_slh_dsa_key(bytes=seed, is_standard=is_standard)
        else:
            reply = jade.sign_slh_dsa(path=[44, 0, 0], message=seed, is_standard=is_standard)
        dt = time.perf_counter() - t0
        times.append(dt)
        print(f'  {i + 1:3d}  {dt:7.3f} s   {len(reply)} bytes')

    print(f'\n  min {min(times):.3f} s   mean {statistics.mean(times):.3f} s   '
          f'max {max(times):.3f} s')
    if len(times) > 1:
        print(f'  stdev {statistics.stdev(times):.3f} s')

    jade.disconnect()


if __name__ == '__main__':
    main()
