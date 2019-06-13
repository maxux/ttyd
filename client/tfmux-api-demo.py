import requests
import time

class TFMuxExample:
    def __init__(self, host="localhost", port=7681):
        self.host = host
        self.port = port

    def endpoint(self, path):
        return "http://%s:%d/api/%s" % (self.host, self.port, path)

    def process_list(self):
        r = requests.get(self.endpoint("/processes")).json()
        return r["processes"]

    def process_clean(self):
        r = requests.get(self.endpoint("/process/clean")).json()
        return (r["status"] == "success")

    def process_start(self, args):
        if type(args) is not list:
            args = [args]

        params = {'arg[]': args}
        r = requests.get(self.endpoint("/process/start"), params=params).json()
        return r

    def process_logs(self, id):
        r = requests.get(self.endpoint("/process/logs"), params={"id": id})
        return r.text

    def process_stop(self, id):
        r = requests.get(self.endpoint("/process/stop"), params={"id": id})
        return r.json()

    def process_kill(self, id, signal=9):
        r = requests.get(self.endpoint("/process/kill"), params={"id": id, "signal": signal})
        return r.json()


if __name__ == '__main__':
    tfmux = TFMuxExample()

    print("[+] fetching processes list")
    plist = tfmux.process_list()

    print("[+] processes found: %d" % len(plist))
    print("[+] ---------------------")

    for process in plist:
        print("[+] process: %s" % process["command"])
        print("[+]   state: %s" % process["state"])
        print("[+]   pid  : %d" % process["pid"])
        print("[+]   id   : %d" % process["id"])
        print("[+] ---------------------")

    print("[+]")
    print("[+] cleaning stopped or crashed processes")
    tfmux.process_clean()

    print("[+] fetching again processes list")
    plist = tfmux.process_list()

    print("[+] remaining processes: %d" % len(plist))
    print("[+] ")

    print("[+] starting a new short-living process (ls /)")
    process = tfmux.process_start(["/bin/ls", "/"])

    print("[+] process created, id: %d" % process["id"])
    print("[+] waiting a little bit for processes to run...")
    time.sleep(1)

    print("[+]")
    print("[+] fetching logs of this process")
    logs = tfmux.process_logs(process["id"])

    print("[+]")
    print("~~~ BEGIN OF LOGS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(logs)
    print("~~~ END OF LOGS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("[+]")

    print("[+] stopping all running processes")
    plist = tfmux.process_list()

    for process in plist:
        tfmux.process_stop(process["id"])

    print("[+] waiting a little bit for processes to end...")
    time.sleep(2)

    print("[+] cleaning stopped or crashed processes")
    tfmux.process_clean()

    print("[+] fetching processes list")
    plist = tfmux.process_list()

    print("[+]")
    print("[+] processes found: %d" % len(plist))
