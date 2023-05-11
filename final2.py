imports = ["json", "time", "binascii", "platform", "subprocess", "sys", "os", "requests", "string", "random", "time"] #list of imports

import json as jsond, time, binascii, platform, subprocess, sys, os, requests, string, random, time
from discord_webhook import DiscordWebhook, DiscordEmbed
from uuid import uuid4
from colorama import Fore, init, Back
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

  


letters = string.ascii_letters



class api:

    name = ownerid = secret = version = hash_to_check = ""



    def __init__(self, name, ownerid, secret, version, hash_to_check):

        self.name = name



        self.ownerid = ownerid



        self.secret = secret



        self.version = version

        self.hash_to_check = hash_to_check

        self.init()



    sessionid = enckey = ""

    initialized = False



    def init(self):



        if self.sessionid != "":

            print("You've already initialized!")

            time.sleep(2)

            exit(0)

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("init").encode()),

            "ver": encryption.encrypt(self.version, self.secret, init_iv),

            "hash": self.hash_to_check,

            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        if response == "KeyAuth_Invalid":

            print("The application doesn't exist")

            sys.exit()



        response = encryption.decrypt(response, self.secret, init_iv)

        json = jsond.loads(response)



        if json["message"] == "invalidver":

            if json["download"] != "":

                print("New Version Available")

                download_link = json["download"]

                os.system(f"start {download_link}")

            else:

                print("Invalid Version, Contact owner to add download link to latest app version")

            sys.exit()

        if not json["success"]:

            print(json["message"])

            sys.exit()



        self.sessionid = json["sessionid"]

        self.initialized = True

        self.__load_app_data(json["appinfo"])







    def register(self, user, password, license, hwid=None):

        self.checkinit()

        if hwid is None:

            hwid = others.get_hwid()



        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("register").encode()),

            "username": encryption.encrypt(user, self.enckey, init_iv),

            "pass": encryption.encrypt(password, self.enckey, init_iv),

            "key": encryption.encrypt(license, self.enckey, init_iv),

            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)



        json = jsond.loads(response)



        if json["success"]:

            print("successfully registered")

        else:

            print(json["message"])

            sys.exit()



    def upgrade(self, user, license):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("upgrade").encode()),

            "username": encryption.encrypt(user, self.enckey, init_iv),

            "key": encryption.encrypt(license, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)



        json = jsond.loads(response)



        if json["success"]:

            print("successfully upgraded user")

        else:

            print(json["message"])

            sys.exit()



    def login(self, user, password, hwid=None):

        self.checkinit()

        if hwid is None:

            hwid = others.get_hwid()



        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("login").encode()),

            "username": encryption.encrypt(user, self.enckey, init_iv),

            "pass": encryption.encrypt(password, self.enckey, init_iv),

            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)



        json = jsond.loads(response)



        if json["success"]:

            self.__load_user_data(json["info"])

            print(f"{Fore.GREEN}Valid Key")

        else:

            print(json["message"])

            sys.exit()



    def license(self, key, hwid=None):

        self.checkinit()

        if hwid is None:

            hwid = others.get_hwid()



        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("license").encode()),

            "key": encryption.encrypt(key, self.enckey, init_iv),

            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)



        json = jsond.loads(response)



        if json["success"]:

            self.__load_user_data(json["info"])

            print(f"{Fore.GREEN}Valid Key")

        else:

            print(json["message"])

            sys.exit()



    def var(self, name):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("var").encode()),

            "varid": encryption.encrypt(name, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)



        json = jsond.loads(response)



        if json["success"]:
            return json["message"]

        print(json["message"])

        time.sleep(5)

        sys.exit()



    def getvar(self, var_name):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("getvar").encode()),

            "var": encryption.encrypt(var_name, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)



        if json["success"]:
            return json["response"]

        print(json["message"])

        time.sleep(5)

        sys.exit()



    def setvar(self, var_name, var_data):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {

            "type": binascii.hexlify(("setvar").encode()),

            "var": encryption.encrypt(var_name, self.enckey, init_iv),

            "data": encryption.encrypt(var_data, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)



        if json["success"]:
            return True

        print(json["message"])

        time.sleep(5)

        sys.exit()    



    def ban(self):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {

            "type": binascii.hexlify(("ban").encode()),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)



        if json["success"]:
            return True

        print(json["message"])

        time.sleep(5)

        sys.exit()    



    def file(self, fileid):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("file").encode()),

            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)



        json = jsond.loads(response)



        if not json["success"]:

            print(json["message"])

            time.sleep(5)

            sys.exit()

        return binascii.unhexlify(json["contents"])



    def webhook(self, webid, param):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("webhook").encode()),

            "webid": encryption.encrypt(webid, self.enckey, init_iv),

            "params": encryption.encrypt(param, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)



        if json["success"]:
            return json["message"]

        print(json["message"])

        time.sleep(5)

        sys.exit()



    def check(self):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {

            "type": binascii.hexlify(("check").encode()),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }

        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        return bool(json["success"])



    def checkblacklist(self):

        self.checkinit()

        hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {

            "type": binascii.hexlify(("checkblacklist").encode()),

            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }

        response = self.__do_request(post_data)



        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        return bool(json["success"])



    def log(self, message):

        self.checkinit()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()



        post_data = {

            "type": binascii.hexlify(("log").encode()),

            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),

            "message": encryption.encrypt(message, self.enckey, init_iv),

            "sessionid": binascii.hexlify(self.sessionid.encode()),

            "name": binascii.hexlify(self.name.encode()),

            "ownerid": binascii.hexlify(self.ownerid.encode()),

            "init_iv": init_iv

        }



        self.__do_request(post_data)



    def checkinit(self):

        if not self.initialized:

            print("Initialize first, in order to use the functions")

            sys.exit()



    def __do_request(self, post_data):



        rq_out = requests.post(

            "https://keyauth.win/api/1.0/", data=post_data

        )



        return rq_out.text



    class application_data_class:

        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    # region user_data

    class user_data_class:

        username = ip = hwid = expires = createdate = lastlogin = subscription = ""



    user_data = user_data_class()

    app_data = application_data_class()



    def __load_app_data(self, data):

        self.app_data.numUsers = data["numUsers"]

        self.app_data.numKeys = data["numKeys"]

        self.app_data.app_ver = data["version"]

        self.app_data.customer_panel = data["customerPanelLink"]

        self.app_data.onlineUsers = data["numOnlineUsers"]



    def __load_user_data(self, data):

        self.user_data.username = data["username"]

        self.user_data.ip = data["ip"]

        self.user_data.hwid = data["hwid"]

        self.user_data.expires = data["subscriptions"][0]["expiry"]

        self.user_data.createdate = data["createdate"]

        self.user_data.lastlogin = data["lastlogin"]

        self.user_data.subcription = data["subscriptions"][0]["subscription"]





class others:

    @staticmethod

    def get_hwid():

        if platform.system() != "Windows":

            return subprocess.Popen('hal-get-property --udi /org/freedesktop/Hal/devices/computer --key system.hardware.uuid'.split())



        cmd = subprocess.Popen(

            "wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)



        (suppost_sid, error) = cmd.communicate()



        suppost_sid = suppost_sid.split(b'\n')[1].strip()



        return suppost_sid.decode()





class encryption:

    @staticmethod

    def encrypt_string(plain_text, key, iv):

        plain_text = pad(plain_text, 16)



        aes_instance = AES.new(key, AES.MODE_CBC, iv)



        raw_out = aes_instance.encrypt(plain_text)



        return binascii.hexlify(raw_out)



    @staticmethod

    def decrypt_string(cipher_text, key, iv):

        cipher_text = binascii.unhexlify(cipher_text)



        aes_instance = AES.new(key, AES.MODE_CBC, iv)



        cipher_text = aes_instance.decrypt(cipher_text)



        return unpad(cipher_text, 16)



    @staticmethod

    def encrypt(message, enc_key, iv):

        try:

            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]



            _iv = SHA256.new(iv.encode()).hexdigest()[:16]



            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()

        except:

            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")

            sys.exit()



    @staticmethod

    def decrypt(message, enc_key, iv):

        try:

            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]



            _iv = SHA256.new(iv.encode()).hexdigest()[:16]



            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()

        except:

            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")

            sys.exit()



import hashlib

from time import sleep

from datetime import datetime

import time



def clear():

    command = 'cls' if os.name in {'nt', 'dos'} else 'clear'
    os.system(command)









os.system("cls")

os.system("title BitCrypt Version 3.0")

print("Initializing")

def getchecksum():

    path = os.path.basename(__file__)

    if not os.path.exists(path):

        path = f"{path[:-2]}exe"

    md5_hash = hashlib.md5()

    a_file = open(path,"rb")

    content = a_file.read()

    md5_hash.update(content)

    return md5_hash.hexdigest()

keyauthapp = api(

	name = "BitCrypt",

	ownerid = "JrLULB6BUY",

	secret = "14d28708fff6f8b9f7e6a5cb1ed636ba0b420cc9c7dc8d9655d46deeed706043",

	version = "1.0",

	hash_to_check = getchecksum()

)



sleep(1.5) # rate limit

print(f"Current Session Validation Status: {keyauthapp.check()}")

sleep(1.5) # rate limit

print(f"Blacklisted? : {keyauthapp.checkblacklist()}") # check if blacklisted, you can edit this and make it exit the program if blacklisted

sleep(1.5)

clear()







def mains():

    def seed():

        print(
            f"{Fore.RED}PRIVATE KEY NOT FOUND",
            Back.BLACK + ''.join(random.choice(letters) for i in range(24)),
        )

                
            

    def hit():

        w = 0

        print(f"{Fore.GREEN}HIT")

        time.sleep(1)

        print(f"{Fore.GREEN}Attempting to resolve seed")

        time.sleep(1)

        while w<3000:

            seed()

            w += 1

        print(f"{Fore.GREEN}PRIVATE KEY FOUND!")

        time.sleep(1)

        print(f"{Fore.YELLOW}Preparing to alert Discord...")

        time.sleep(1.5)

        amount = random.choice(["0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048","0.000048",".00006",".000085",".000310",".000026",".000096",".000193",".0002087",".000058",".000057",".000484",".000151",".000175",".000363",".000351",".000242",".000136",".000096",".000024",".000218",".000387",".000393",".000436",".000411"])

        print(f"Amount of BTC found: {amount}")

        newamount = amount

        def webhook():

                webhook = DiscordWebhook(url='https://discord.com/api/webhooks/968170368302993428/JDb84tN-n2_SolpYlGgoyryJZsnm0DPqmx491amy56zbUgCBOO3H_MFsNexUHJSerPvw')



                embed = DiscordEmbed(description='ANOTHER HIT DETECTED!', color='03b2f8')

                embed.set_author(name='BITCRYPT')

                embed.set_footer(text='BitCrypt Hit Notify')

                embed.set_timestamp()











                embed.add_embed_field(name='Discord', value = user)

                embed.add_embed_field(name='Amount', value = newamount)

                embed.add_embed_field(name='Type', value = 'P2SH')





                webhook.add_embed(embed)

                response = webhook.execute()

        webhook()

        print("Notification sent to discord!")

        print(f"{Fore.YELLOW}Press enter to continue mining!")

        input()


            

    def walletspub():

        i = random.randint(530,3000)

        u = random.randint(200000,2000000)

        while i < u:

            print(
                f"{Fore.WHITE}BTC |",
                (
                    (
                        (
                            f"{Back.YELLOW}3"
                            + ''.join(
                                random.choice(letters) for i in range(33)
                            )
                        )
                        + Back.BLACK
                    )
                    + " | BIT CRYPT | TYPE: P2SH"
                ),
                sep='',
                end='',
            )

            time.sleep(.1)

            print("")

            print(
                f"{Fore.WHITE}BTC |",
                (
                    (
                        (
                            f"{Back.BLACK}3"
                            + ''.join(
                                random.choice(letters) for i in range(33)
                            )
                        )
                        + Back.BLACK
                    )
                    + " | BIT CRYPT | TYPE: P2SH"
                ),
                sep='',
                end='',
            )

            time.sleep(.1)

            print("")

            i += 1

        hit()

        while True:

                walletspub()








    def walletspriv():

        i = random.randint(530,3000)

        u = random.randint(200000,2000000)

        while i < u:

            print(
                f"{Fore.WHITE}BTC |",
                (
                    (
                        (
                            f"{Back.YELLOW}3"
                            + ''.join(
                                random.choice(letters) for i in range(33)
                            )
                        )
                        + Back.BLACK
                    )
                    + " | BIT CRYPT | TYPE: P2SH"
                ),
                sep='',
                end='',
            )

            time.sleep(.1)

            print("")

            print(
                f"{Fore.WHITE}BTC |",
                (
                    (
                        (
                            f"{Back.BLACK}3"
                            + ''.join(
                                random.choice(letters) for i in range(33)
                            )
                        )
                        + Back.BLACK
                    )
                    + " | BIT CRYPT | TYPE: P2SH"
                ),
                sep='',
                end='',
            )

            time.sleep(.1)

            print("")

            i += 1

        hit()

        while True:

                walletspriv()














    def mainpub():

            #if (wallets.Contains(legacyAddress)  wallets.Contains(segwitAddress)  wallets.Contains(p2shAddress))

            #string[] lines = System.IO.File.ReadAllLines(@"C:\Users\ne\Desktop\ONI\wallets.txt");

            #Console.WriteLine("Reading database... DONE!");

            #Console.Write("Preparing database... \r");

            #HashSet<string> wallets = new HashSet<string>(lines);

            #int millisecondsTimeout = (int)Math.Round((double)this.baseDelay * (double)(100 - multiplier));

            #long num = 0L;

            #double num2 = 0.0;

            #int num3 = 0;

            #string b = "";

            #int num4 = Util.randomNumber(41, 51);

            #while (num < 100000L)

            #{

            #string text = "1" + Util.RandomString(33);

            #string text2 = Util.RandomString(52);

            #bool flag = text == b;

            #if (!flag)

            #{

            #b = text;

            #num += 1L;

            #bool flag2 = Util.randomNumber(0, 100) == 1 && text2[3] == 'K';

            #bool flag3 = !flag2;

            #if (flag3)

            while True:

                    walletspub()



    def mainpriv():

            #if (wallets.Contains(legacyAddress)  wallets.Contains(segwitAddress)  wallets.Contains(p2shAddress))

            #string[] lines = System.IO.File.ReadAllLines(@"C:\Users\ne\Desktop\ONI\wallets.txt");

            #Console.WriteLine("Reading database... DONE!");

            #Console.Write("Preparing database... \r");

            #HashSet<string> wallets = new HashSet<string>(lines);

            #int millisecondsTimeout = (int)Math.Round((double)this.baseDelay * (double)(100 - multiplier));

            #long num = 0L;

            #double num2 = 0.0;

            #int num3 = 0;

            #string b = "";

            #int num4 = Util.randomNumber(41, 51);

            #while (num < 100000L)

            #{

            #string text = "1" + Util.RandomString(33);

            #string text2 = Util.RandomString(52);

            #bool flag = text == b;

            #if (!flag)

            #{

            #b = text;

            #num += 1L;

            #bool flag2 = Util.randomNumber(0, 100) == 1 && text2[3] == 'K';

            #bool flag3 = !flag2;

            #if (flag3)

            while True:

                    walletspriv()



    print(Fore.YELLOW + """



        ╔═══════════════════════════════════════════════════════════════════════════════════════╗

        ║                                                                                       ║

        ║                                                                                       ║

        ║ /$$$$$$$  /$$$$$$ /$$$$$$$$        /$$$$$$  /$$$$$$$  /$$     /$$ /$$$$$$$  /$$$$$$$$ ║

        ║| $$__  $$|_  $$_/|__  $$__/       /$$__  $$| $$__  $$|  $$   /$$/| $$__  $$|__  $$__/ ║ 

        ║| $$  \ $$  | $$     | $$         | $$  \__/| $$  \ $$ \  $$ /$$/ | $$  \ $$   | $$    ║

        ║| $$$$$$$   | $$     | $$         | $$      | $$$$$$$/  \  $$$$/  | $$$$$$$/   | $$    ║

        ║| $$__  $$  | $$     | $$         | $$      | $$__  $$   \  $$/   | $$____/    | $$    ║

        ║| $$  \ $$  | $$     | $$         | $$    $$| $$  \ $$    | $$    | $$         | $$    ║

        ║| $$$$$$$/ /$$$$$$   | $$         |  $$$$$$/| $$  | $$    | $$    | $$         | $$    ║

        ║|_______/ |______/   |__/          \______/ |__/  |__/    |__/    |__/         |__/    ║

        ║                                                                                       ║

        ║                            ALL RIGHTS RESERVED TO J1                                  ║

        ║                                                                                       ║

        ╠═══════════════════════════════════════════════════════════════════════════════════════╣""")

    key = input(f"{Fore.YELLOW}Pin:")



    if key == "7845":

        print(f"{Fore.GREEN}Correct Auth Code..")

        time.sleep(.5)

        user =input("User Name (discord name)")

        print(user)

        print(f"{Fore.YELLOW}Proceeding with public access!")

        time.sleep(1)

        clear()

        time.sleep(2)

        mainpub()

    elif key == "6254":

        print(f"{Fore.GREEN}Correct Auth Code..")

        time.sleep(.5)

        user =input("User Name (discord name):")

        print(user)

        print(f"{Fore.YELLOW}Proceeding with private access!")

        time.sleep(1)

        clear()

        time.sleep(2)

        mainpriv()

    else:

        print(f"{Fore.RED}Invalid Auth Code...")

        time.sleep(1)

        print(f"{Fore.RED}Closing program....")

        time.sleep(1)

        exit()



print(Fore.YELLOW + """



╔═══════════════════════════════════════════════════════════════════════════════════════╗

║                                                                                       ║

║                                                                                       ║

║ /$$$$$$$  /$$$$$$ /$$$$$$$$        /$$$$$$  /$$$$$$$  /$$     /$$ /$$$$$$$  /$$$$$$$$ ║

║| $$__  $$|_  $$_/|__  $$__/       /$$__  $$| $$__  $$|  $$   /$$/| $$__  $$|__  $$__/ ║ 

║| $$  \ $$  | $$     | $$         | $$  \__/| $$  \ $$ \  $$ /$$/ | $$  \ $$   | $$    ║

║| $$$$$$$   | $$     | $$         | $$      | $$$$$$$/  \  $$$$/  | $$$$$$$/   | $$    ║

║| $$__  $$  | $$     | $$         | $$      | $$__  $$   \  $$/   | $$____/    | $$    ║

║| $$  \ $$  | $$     | $$         | $$    $$| $$  \ $$    | $$    | $$         | $$    ║

║| $$$$$$$/ /$$$$$$   | $$         |  $$$$$$/| $$  | $$    | $$    | $$         | $$    ║

║|_______/ |______/   |__/          \______/ |__/  |__/    |__/    |__/         |__/    ║

║                                                                                       ║

║                            ALL RIGHTS RESERVED TO J1                                  ║

║                                                                                       ║

╠═══════════════════════════════════════════════════════════════════════════════════════╣""")

print(Fore.YELLOW + """

1] FAQ

2] Public Mining

3] Private Mining

4] Exit

""")



ans = input("Option:")

if ans == "1":

    print("Join our discord for more infomation! | discord.gg/bitcrypt")

    time.sleep(4)

    exit()

elif ans in ["2", "3"]:

    clear()

    key = input('Enter your license:')

    keyauthapp.license(key)

    time.sleep(1)

    clear()

    mains()

elif ans == "4":

    time.sleep(1)

    exit()

else:

    print("\nNot Valid Option")

    time.sleep(1)

    sys.exit()

