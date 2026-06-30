from jadepy.jade import JadeAPI
import time
import os

def timed(label, fn):
    t0 = time.perf_counter()
    result = fn()
    dt = time.perf_counter() - t0
    print(f"{label:28s} {dt*1000:9.1f} ms   sig={len(result)} bytes")
    return result

# You may need to change device !!!
# tcp:localhost:30121
# /dev/cu.usbmodem1234561
jade = JadeAPI.create_serial(device='/dev/cu.usbmodem1234561')
info = jade.connect()

# jade.set_mnemonic('all all all all all all all all sleep all all all')

# zero = 0
# message = zero.to_bytes(32, "big")

# s1 = timed("shrincs swn=140",  lambda: jade.sign_shrincs(path=[44,0,0], message=message, swn=140))
# s2 = timed("shrincs swn=96",   lambda: jade.sign_shrincs(path=[44,0,0], message=message, swn=96))
# s3 = timed("slh_dsa standard", lambda: jade.sign_slh_dsa(path=[44,0,0], message=message, is_standard=True))
# s4 = timed("slh_dsa custom",   lambda: jade.sign_slh_dsa(path=[44,0,0], message=message, is_standard=False))

start = time.time()
for x in range(20):
    response = jade.gen_shrincs_key(bytes=x.to_bytes(32, "big"))
    elapsed = time.time() - start
    print(f"Keygen: {elapsed / (x+1):.2f}s, root size: {len(response)} bytes")

jade.disconnect()