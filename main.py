from tlsclient import *

def main():
    client_random = gen_random(32)
    client_hello = TLSClientHelloFrame()
    client_hello.random = client_random
    client_hello.extensions.append(TLSExtension(43, [3, 4]))
    client_hello_binary = client_hello.get_binary()
    for i in range(len(client_hello_binary)):
        if i % 16 == 15 or i+1 == len(client_hello_binary):
            print("{:0>2x}".format(client_hello_binary[i]))
        else:
            print("{:0>2x}".format(client_hello_binary[i]), end=" ")

if __name__ == "__main__":
    main()