from jadepy.jade import JadeAPI

# QEMU: serial-канал прошивки виставлений по TCP на 30121
jade = JadeAPI.create_serial(device='tcp:localhost:30121')
info = jade.connect()
print("connected:", info)

jade.set_mnemonic('all all all all all all all all sleep all all all')

sig = jade.sign_shrincs(path=[44, 0, 0], message="hello")
print(bytes.hex(sig))
jade.disconnect()