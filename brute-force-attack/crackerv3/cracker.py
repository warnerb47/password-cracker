
import hashlib
import itertools
import multiprocessing
import os
import string
import threading
import time
from hash_identifier import getHashes



class Cracker(object):

    ALPHA_LOWER = (string.ascii_lowercase,)
    ALPHA_UPPER = (string.ascii_uppercase,)
    ALPHA_MIXED = (string.ascii_lowercase, string.ascii_uppercase)

    def __init__(self, hash_type, hash, charset, progress_interval):
        self.__charset = charset
        self.__curr_iter = 0
        self.__prev_iter = 0
        self.__curr_val = ""
        self.__progress_interval = progress_interval
        self.__hash_type = hash_type
        self.__hash = hash
        self.__hashers = {}


    def __init_hasher(self):
        hashlib_type = self.__hash_type if self.__hash_type != "ntlm" else "md4"
        self.__hashers[self.__hash_type] = hashlib.new(hashlib_type)

    def __encode_utf8(self, data):
        return data.encode("utf-8")

    def __encode_utf16le(self, data):
        return data.encode("utf-16le")


    @staticmethod
    def __search_space(charset, maxlength):

        return (
            ''.join(candidate) for candidate in
            itertools.chain.from_iterable(
                itertools.product(charset, repeat=i) for i in
                range(1, maxlength + 1)
            )
        )


    def __attack(self, q, max_length):
        self.__init_hasher()
        self.start_reporting_progress()
        hash_fn = self.__encode_utf8 if self.__hash_type != "ntlm" else self.__encode_utf16le
        for value in self.__search_space(self.__charset, max_length):
            hasher = self.__hashers[self.__hash_type].copy()
            self.__curr_iter += 1
            self.__curr_val = value
            hasher.update(hash_fn(value))
            if self.__hash == hasher.hexdigest():
                q.put("FOUND")
                q.put("{}Match found! Password is {}{}".format(os.linesep, value, os.linesep))
                self.stop_reporting_progress()
                return

        q.put("NOT FOUND")
        self.stop_reporting_progress()

    @staticmethod
    def work(work_q, done_q, max_length):
        obj = work_q.get()
        obj.__attack(done_q, max_length)

    def start_reporting_progress(self):
        self.__progress_timer = threading.Timer(self.__progress_interval, self.start_reporting_progress)
        self.__progress_timer.start()
        print(
            f"Character set: {self.__charset}, iteration: {self.__curr_iter}, trying: {self.__curr_val}, hashes/sec: {self.__curr_iter - self.__prev_iter}",
            flush=True)
        self.__prev_iter = self.__curr_iter

    def stop_reporting_progress(self):
        self.__progress_timer.cancel()
        print(f"Finished character set {self.__charset} after {self.__curr_iter} iterations", flush=True)


def get_password_length():
    prompt = "{}Specify the length of the password: ".format(os.linesep)
    while True:
        try:
            password_length = int(input(prompt))
        except ValueError:
            print("{}Password length must be an integer".format(os.linesep))
            continue
        else:
            break
    return password_length

def get_user_hash():
    prompt = "{}Specify the hash to be attacked: ".format(os.linesep)
    while True:
        try:
            user_hash = input(prompt)
        except ValueError:
            print("{}Something is wrong with the format of the hash. Please enter a valid hash".format(os.linesep))
            continue
        else:
            break
    return user_hash

def main():
    password_length = get_password_length()
    user_hash = get_user_hash()
    hash_type_list = getHashes(user_hash)

    if len(hash_type_list) > 1:
        hash_type = hash_type_list[0].lower()

        print(f"Trying to crack hash {user_hash}", flush=True)
        print(hash_type, "hash type Found")
        processes = []
        work_queue = multiprocessing.Queue()
        done_queue = multiprocessing.Queue()
        progress_interval = 3
        cracker = Cracker(hash_type.lower(), user_hash.lower(), ''.join(Cracker.ALPHA_MIXED), progress_interval)
        start_time = time.time()
        p = multiprocessing.Process(target=Cracker.work,
                                    args=(work_queue, done_queue, password_length))
        processes.append(p)
        work_queue.put(cracker)
        p.start()
        if len(Cracker.ALPHA_MIXED) > 1:
            for i in range(len(Cracker.ALPHA_MIXED)):
                progress_interval += .2
                cracker = Cracker(hash_type.lower(), user_hash.lower(), Cracker.ALPHA_MIXED[i], progress_interval)
                p = multiprocessing.Process(target=Cracker.work,
                                            args=(work_queue, done_queue, password_length))
                processes.append(p)
                work_queue.put(cracker)
                p.start()
        failures = 0
        while True:
            data = done_queue.get()
            if data == "NOT FOUND":
                failures += 1
            elif data == "FOUND":
                print(done_queue.get())
                for p in processes:
                    p.terminate()

                break

            if failures == len(processes):
                print("{}No matches found{}".format(os.linesep, os.linesep))
                break

        print("Took {} seconds".format(time.time() - start_time))
    else:
        print("Hash type not found")       

main()