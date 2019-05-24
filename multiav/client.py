#!/usr/bin/env python

import os
import sys
import json
import pprint
import time
import requests

from multiav.core import AV_SPEED
from subprocess import check_output
from multiav.parallelpromise import ParallelPromise

#-----------------------------------------------------------------------
class MultiAVClient:
  def __init__(self, host):
    self.host = host

  def scan(self, filename, minspeed=AV_SPEED.ALL, allow_internet=False, dont_pull_result=False):
    def upload_function(resolve, reject, dont_pull_result):
      try:
        # setup parameters
        multipart_form_data = {
            'file_upload': (os.path.basename(filename), open(filename, 'rb')),
            'minspeed': (None, str(minspeed.value)),
            'allow_internet': (None, "true" if allow_internet else "false"),
        }

        # send request
        response = requests.post(self.host + "/api/upload", files=multipart_form_data)
        response = response.json()

        if response is None:
          raise Exception("invalid response from host")
        
        if response["file"]["name"] != os.path.basename(filename):
          raise Exception("filenames of report and upload don't match!")

        # pull the result?
        if dont_pull_result:
          resolve(response)

        # get report id from response
        report_id = response["id"]
        report_finished = False

        # query report and return as soon as the report has no queued or scanning entries
        while not report_finished:
          # setup parameters
          multipart_form_data = {
              'id': (None, str(report_id))
          }

          # send request
          response = requests.post(self.host + "/api/report", files=multipart_form_data)
          report = response.json()

          # check if there are scanning or queued items in it
          report_finished = len(report["end_date"]) != 0
          
          if not report_finished:
            # wait some seconds before requering
            #print("report not finished yet. rechecking in 5s...")
            time.sleep(5)
            continue
          
          resolve(report)
      except Exception as e:
        print("[MultiAVClient] Exception: {0}".format(e))
        print(e)
        reject(e)
        return

    return ParallelPromise(lambda resolve, reject: upload_function(resolve, reject, dont_pull_result))

#-----------------------------------------------------------------------
def usage():
  print("Usage:", sys.argv[0], "<multi-av host> <filename> [--minspeed speed] [--allow-internet]")

#-----------------------------------------------------------------------
def main(url, filename, minspeed=AV_SPEED.ALL, allow_internet=False):
  def print_result(res):
    print(" ")
    print("[MultiAVClient] Scan finished:")
    pprint.pprint(res)

  scanner = MultiAVClient(url)
  scan_promise = scanner.scan(filename, minspeed, allow_internet)
  scan_promise.then(
    lambda res: print_result(res),
    lambda res: print_result(res)
  )
  print("scan scheduled. waiting for result (could take a while...)")
  scan_promise.wait()

if __name__ == "__main__":
  print("[MultiAVClient]")
  if len(sys.argv) < 3:
    usage()
  else:
    allow_internet = False
    minspeed = AV_SPEED.ALL

    # handle optional args
    if len(sys.argv) > 3:
      remaining_args = sys.argv[3:]
      for arg in remaining_args:
        if arg == "--allow-internet":
          allow_internet = True
          print("- internet access allowed")
        elif arg == "--minspeed":
          minspeed = AV_SPEED(int(remaining_args[remaining_args.index(arg) + 1]))
          print("- minspeed set to {0}".format(minspeed.value))

    main(sys.argv[1], sys.argv[2], minspeed=minspeed, allow_internet=allow_internet)
