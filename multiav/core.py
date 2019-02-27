# -*- coding: utf-8 -*-

#-----------------------------------------------------------------------
# MultiAV scanner wrapper version 0.0.1
# Copyright (c) 2014, Joxean Koret
#
# License:
#
# MultiAV is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# MultiAV is distributed in the hope that it will be  useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser Public License for more details.
#
# You should have received a copy of the GNU Lesser Public License
# along with DoctestAll.  If not, see
# <http://www.gnu.org/licenses/>.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# Description:
#
# This script implements a very basic wrapper around various AV engines
# available for Linux using their command line scanners with the only
# exception of ClamAV. The currently supported AV engines are listed
# below:
#
#   * ClamAV (Fast)
#   * F-Prot (Fast)
#   * Comodo (Fast)
#   * BitDefender (Medium)
#   * ESET (Slow)
#   * Avira (Slow)
#   * Sophos (Medium)
#   * Avast (Fast)
#   * AVG (Fast)
#   * DrWeb (Slow)
#   * McAfee (Very slow, only enabled when running all the engines)
#   * Ikarus (Medium, using wine in Linux/Unix)
#   * F-Secure (Fast)
#   * Kaspersky (Fast)
#   * Zoner Antivirus (Fast)
#   * MicroWorld-eScan (Fast)
#   * Cyren (Fast)
#   * QuickHeal (Fast)
#
# Support for the Kaspersky AV engine includes MacOSX, Windows, and Linux
#
# Features:
#
#   * Parallel scan, by default, based on the number of CPUs.
#   * Analysis by AV engine speed.
#
#-----------------------------------------------------------------------

import os
import re
import codecs
import time
import ConfigParser
import xml.etree.ElementTree
import requests
import json
import random

from rwlock import RWLock
from enum import Enum
from hashlib import sha1
from tempfile import NamedTemporaryFile
from subprocess import check_output, CalledProcessError, call, STDOUT
from multiprocessing import Process, Queue, cpu_count
from datetime import datetime

try:
    import pyclamd
    has_clamd = True
except ImportError:
    has_clamd = False

# -----------------------------------------------------------------------
class OrderedEnum(Enum):
  def __ge__(self, other):
    if self.__class__ is other.__class__:
      return self.value >= other.value
    return NotImplemented
  def __gt__(self, other):
    if self.__class__ is other.__class__:
      return self.value > other.value
    return NotImplemented
  def __le__(self, other):
    if self.__class__ is other.__class__:
      return self.value <= other.value
    return NotImplemented
  def __lt__(self, other):
    if self.__class__ is other.__class__:
      return self.value < other.value
    return NotImplemented
    
class EnumEncoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, Enum):
        return obj.value
    return json.JSONEncoder.default(self, obj)

class AV_SPEED(OrderedEnum):
  ALL = 3  # Run only when all engines must be executed
  SLOW = 2
  MEDIUM = 1
  FAST = 0
  ULTRA = -1

class PLUGIN_TYPE(OrderedEnum):
  LEGACY = 0
  AV = 1
  METADATA = 2
  INTEL = 3
  FILE_FORMATS = 4

DOCKER_NETWORK_NO_INTERNET_NAME = "multiav-no-internet-bridge"
DOCKER_NETWORK_INTERNET_NAME = "multiav-internet-bridge"

# -----------------------------------------------------------------------
class CAvScanner:
  def __init__(self, cfg_parser):
    self.cfg_parser = cfg_parser
    self.name = None
    self.speed = AV_SPEED.SLOW
    self.results = {}
    self.file_index = 0
    self.malware_index = 1
    self.scan_output_pattern = None
    self.binary_version_pattern = None
    self.engine_data_version_pattern = None
    self.update_check_pattern = None
    self.plugin_type = PLUGIN_TYPE.LEGACY

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    args.extend(scan_args.split(" "))
    args.append(path)
    return args

  def scan(self, path):
    if self.scan_output_pattern is None:
      Exception("Not implemented")

    try:
      cmd = self.build_cmd(path)
    except: # There is no entry in the *.cfg file for this AV engine?
      pass

    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    scan_output_pattern = self.scan_output_pattern
    matches = re.findall(scan_output_pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      self.results[match[self.file_index]] = match[self.malware_index]
    return len(self.results) > 0

  def is_disabled(self):
    parser = self.cfg_parser
    try:
      self.cfg_parser.get(self.name, "DISABLED")
      return True
    except:
      return False
  
  def update(self):
    try:
      cmd = self.cfg_parser.get(self.name, "UPDATE").split(' ')
    except ConfigParser.NoOptionError:
      print("Update not supported by scanner: {0}".format(self.name))
      return False
    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output
    except:
      return False

    print("Output update: {0}".format(output))

    return True

  def get_signature_version(self):
    return "-"

#-----------------------------------------------------------------------
class CMalicePlugin(CAvScanner):
  def __init__(self, cfg_parser, name):
    CAvScanner.__init__(self, cfg_parser)
    self.name = name
    self.container_name = None
    self.plugin_id = cfg_parser.get(self.name, "PLUGIN_ID")
    self.docker_network_no_internet = self.cfg_parser.get("MULTIAV", "DOCKER_NETWORK_NO_INTERNET").split(".") #[10,192,212,0]
    self.docker_network_internet = self.cfg_parser.get("MULTIAV", "DOCKER_NETWORK_INTERNET").split(".") #[10,168,137,0]
    self.container_api_endpoint = "scan"
    self.container_api_sample_parameter_name = "malware"

    if self.cfg_parser.has_option(self.name, "ENABLE_INTERNET_ACCESS"):
      self.container_requires_internet = int(self.cfg_parser.get(self.name, "ENABLE_INTERNET_ACCESS")) == 1
    else:
      self.container_requires_internet = False

    self.container_api_host = self.get_api_host()
    self.container_api_port = 3993

    self.container_run_command_arguments = dict()
    self.container_run_docker_parameters = dict()
    self.container_build_params = dict()

    if self.cfg_parser.has_option(self.name, "DOCKER_BUILD_URL_OVERRIDE"):
      self.container_build_url_override = self.cfg_parser.get(self.name, "DOCKER_BUILD_URL_OVERRIDE")
    else:
      self.container_build_url_override = None
  
  def get_api_host(self):
    ip = []
    if self.container_requires_internet:
      ip = self.docker_network_internet[0:3]
    else:
      ip = self.docker_network_no_internet[0:3]

    # add host
    ip.append(self.plugin_id)
    
    return ".".join(ip)

  def is_container_running(self):
    cmd = "docker ps --filter status=running"
    output = str(check_output(cmd.split(" ")))
    return "malice/" + self.container_name in output

  def is_container_created(self):
    cmd = "docker ps -a"
    output = str(check_output(cmd.split(" ")))
    return "malice/" + self.container_name in output

  def get_container_tag(self):
    cmd = "docker images malice/{0}:updated".format(self.container_name)
    output = str(check_output(cmd.split(" ")))

    return "updated" if self.container_name in output else "latest"

  def start_container(self):
    tag = self.get_container_tag()

    network_name = DOCKER_NETWORK_INTERNET_NAME if self.container_requires_internet else DOCKER_NETWORK_NO_INTERNET_NAME
    cmd = "docker run -d --name {0} --net {3} --ip {1}$DOCKERPARAMS$ --rm malice/{0}:{2}$CMDARGS$ web".format(self.container_name, self.container_api_host, tag, network_name)

    # set docker parameters
    if len(self.container_run_docker_parameters) == 0:
      cmd = cmd.replace("$DOCKERPARAMS$", "")
    else:
      cmd = cmd.replace("$DOCKERPARAMS$", " " + " ".join(
        map(lambda kv: kv[0] + "=" + kv[1], self.container_run_docker_parameters.items())))
        
    # set command arguments
    if len(self.container_run_command_arguments) == 0:
      cmd = cmd.replace("$CMDARGS$", "")
    else:
      cmd = cmd.replace("$CMDARGS$", " " + " ".join(map(lambda kv: kv[0] + "=" + kv[1], self.container_run_command_arguments.items())))
    
    # start
    try:
      check_output(cmd.split(" "))
    except Exception as e:
      print(cmd)
      print(e)
      return False

    # give the container a sec to start
    time.sleep(1)

    return self.is_container_running()
  
  def stop_container(self):
    cmd = "docker stop {0}".format(self.container_name)
    output = str(check_output(cmd.split(" ")))
    return self.container_name in output
  
  def restart_container(self):
    if self.stop_container():
      return self.start_container()
    return False

  def remove_container(self):
    cmd = "docker rm {0}".format(self.container_name)
    output = str(check_output(cmd.split(" ")))

    return self.container_name in output

  def is_container_pulled(self):
    #latest must always exist
    cmd = "docker images malice/{0}:latest".format(self.container_name)
    output = str(check_output(cmd.split(" ")))
    
    return self.container_name in output

  def pull_container(self):
    if self.is_container_pulled():
      return True

    if self.container_build_url_override != None or len(self.container_build_params) != 0:
      container_url = ""
      if self.container_build_url_override:
        container_url = self.container_build_url_override
      else:
        container_url = "https://github.com/malice-plugins/{0}.git".format(self.container_name)
      
      print("building docker container malice/{0} from url: {1}".format(self.container_name, container_url))
      cmd = "docker build --tag malice/{0}:latest$BUILDARGS$ {1}".format(self.container_name, container_url)

      # set build params (e.g license keys)
      if len(self.container_build_params) == 0:
        cmd = cmd.replace("$BUILDARGS$", "")
      else:
        cmd = cmd.replace("$BUILDARGS$", "".join(map(lambda kv: " --build-arg " + kv[0] + "=" + kv[1], self.container_build_params.items())))

      output = str(check_output(cmd.split(" ")))

      if not "Successfully built" in output:
        print(output)
        return False

      print("Built container for plugin {0} successfully!".format(self.container_name))

    else:
      print("pulling docker container malice/{0}".format(self.container_name))
      cmd = "docker pull malice/" + self.container_name

      output = str(check_output(cmd.split(" ")))

      if not "Status: Downloaded newer image" in output:
        print(output)
        return False

      print("Pulled container for plugin {0} successfully!".format(self.container_name))
    
    return True
  
  def store_results(self, response_obj):
    if self.plugin_type == PLUGIN_TYPE.AV:
      self.results = response_obj[response_obj.keys()[0]]
    elif self.plugin_type == PLUGIN_TYPE.METADATA or self.plugin_type == PLUGIN_TYPE.FILE_FORMATS:
      self.results = response_obj
    elif self.plugin_type == PLUGIN_TYPE.INTEL:
      if len(response_obj.keys()) == 1:
        self.results = response_obj[response_obj.keys()[0]]
      else:
        self.results = response_obj

  def scan(self, path):
    retry_counter = 0
    while retry_counter < 3:
      try:
        if not self.is_container_running():
          if not self.is_container_pulled():
            print("docker image for malice plugin {0} not pulled! use docker pull malice/{0} to set it up or set auto_pull=True!".format(self.container_name))
            return False
          
          self.start_container()
          time.sleep(5)

        # build request params
        url = "http://{0}:{1}/{2}".format(self.container_api_host, self.container_api_port, self.container_api_endpoint)
        filename = os.path.basename(path)
        
        files = {
          self.container_api_sample_parameter_name: (filename, open(path, 'rb'))
          }

        # post
        start_time = time.time()
        response = requests.post(url, files=files, timeout=120)
        print("[{0}] Scan time: {1}s seconds".format(self.name, (time.time() - start_time)))
        response_obj = json.loads(response.text)
        
        # store
        self.store_results(response_obj)
        
        return True

      except Exception as e:
        retry_counter += 1
        self.results = { 
          "error": "{0}".format(e),
          "infected": False,
          "engine": "-",
          "updated": "-",
          "has_internet": self.container_requires_internet,
          "speed": self.speed.name
        }
        print("[{0}] Exception in scan method".format(self.name))
        print(e)
      
      print("[{0}] Error while scanning the file. retrying now (counter {1})...".format(self.container_name, retry_counter))
      #time.sleep(random.randint(2,25))

    return False

  def update(self):
    # stop container
    if self.is_container_running():
      print("[{0}] is running. Stopping now...".format(self.container_name))
      self.stop_container()

      # give docker some time to stop the container
      time.sleep(5)

    
    if not self.is_container_pulled():
      print("[{0}] Update failed. Container not pulled!".format(self.container_name))
      return "error"
    
    # Check for docker image update on the store
    #try:
    #  cmd = "docker pull malice/{0}".format(self.container_name)
    #  output = check_output(cmd.split(" "))
    #except Exception as e:
    #  self.start_container()
    #  return False

    # cleanup old update image if existing
    try:
      cmd = "docker images malice/{0}:updated".format(self.container_name)
      output = str(check_output(cmd.split(" ")))

      if self.container_name in output:
        print("[{0}] cleanup old updated container".format(self.container_name))
        cmd = "docker rmi malice/{0}:updated".format(self.container_name)
        output = str(check_output(cmd.split(" ")))
    except Exception as e:
      print("[{0}] {1}".format(self.container_name, e))
      self.start_container()
      return "error"
    
    # run new container to do the update
    try:
      cmd = "docker run --name {0} malice/{0}:latest update".format(self.container_name)
      output = str(check_output(cmd.split(" ")))
    except Exception as e:
      print("[{0}] {1}".format(self.container_name, e))
      self.start_container()
      return "error"
    

    # save updated container as new image with tag updated
    try:
      cmd = "docker commit {0} malice/{0}:updated".format(self.container_name)
      output = str(check_output(cmd.split(" ")))
    except Exception as e:
      print("[{0}] {1}".format(self.container_name, e))
      self.remove_container()
      self.start_container()
      return "error"
    
    # remove the container used for updating
    if not self.remove_container():
      print("[{0}] {1}".format(self.container_name, "could not remove the updated container"))
      self.start_container()
      return "error"


    # start the updated container
    if not self.start_container():
      print("[{0}] could not start container {0}".format(self.container_name))
      return "error"

    return "success"

  def get_signature_version(self):
    try:
      # 2>/dev/null => hide possible error messages if the update file doesnt exist
      cmd = "docker exec {0} cat /opt/malice/UPDATED".format(self.container_name)
      FNULL = open(os.devnull, 'w')
      output = str(check_output(cmd.split(" "), stderr=FNULL))
    except:
      output = "-"
    
    return output

#-----------------------------------------------------------------------
class CMaliceHashPlugin(CMalicePlugin):
  def __init__(self, cfg_parser, name):
    CMalicePlugin.__init__(self, cfg_parser, name)
  
  def scan(self, path):
    retry = 0
    while retry <= 1:
      try:
        if not self.is_container_running():
          if not self.is_container_pulled():
            print("docker image for malice plugin {0} not pulled! use docker pull malice/{0} to set it up!".format(self.container_name))
            return False
          
          self.start_container()
          time.sleep(5)

        with open(path, "rb") as binary_file:
          # Read the whole file at once
          buf = binary_file.read()

        # build request params
        url = "http://{0}:{1}/{2}/{3}".format(self.container_api_host, self.container_api_port, self.container_api_endpoint, sha1(buf).hexdigest())

        # post
        start_time = time.time()
        response = requests.get(url, timeout=120)
        print("[{0}] Scan time: {1}s seconds".format(self.name, (time.time() - start_time)))
        response_obj = json.loads(response.text)

        # store
        self.store_results(response_obj)
        
        return True

      except Exception as e:
        print(e)
        self.results = { "exception": e }
        retry += 1
        self.restart_container()
        time.sleep(10)
  
    return False

#-----------------------------------------------------------------------
class CFileInfo(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "FileInfoMalice")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.METADATA
    self.container_name = "fileinfo"
  
  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CPEScanMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "PEScanMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.FILE_FORMATS
    self.container_name = "pescan"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CFlossMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "FlossMalice")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.FILE_FORMATS
    self.container_name = "floss"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
# Update and download servers not reachable anymore :/
'''class CZonerMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "ZonerMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "zoner"
    self.container_api_port = cfg_parser.get(self.name, "API_PORT")
    self.container_restart_after_query = cfg_parser.get(self.name, "RESTART_CONTAINER_AFTER_QUERY")
    self.container_enviroment_variables["ZONE_KEY"] = cfg_parser.get(self.name, "LICENSE_KEY")'''

#-----------------------------------------------------------------------
class CWindowsDefenderMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "WindowsDefenderMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "windows-defender"
    self.container_run_docker_parameters["--security-opt"] = "seccomp=seccomp.json"

#-----------------------------------------------------------------------
class CSophosMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "SophosMalice")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "sophos"

#-----------------------------------------------------------------------
class CAvastMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "AvastMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avast"

  def update(self):
    return "skipped"

#-----------------------------------------------------------------------
class CAvgMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "AvgMalice")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avg"

#-----------------------------------------------------------------------
class CBitDefenderMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "BitDefenderMalice")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "bitdefender"
    self.container_build_params["BDKEY"] = cfg_parser.get(self.name, "LICENSE_KEY")

#-----------------------------------------------------------------------
class CClamAVMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "ClamAVMalice")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "clamav"

#-----------------------------------------------------------------------
class CComodoMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "ComodoMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "comodo"

#-----------------------------------------------------------------------
class CDrWebMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "DrWebMalice")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "drweb"

#-----------------------------------------------------------------------
class CEScanMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "EScanMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "escan"

#-----------------------------------------------------------------------
class CFProtMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "FProtMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "fprot"

#-----------------------------------------------------------------------
class CFSecureMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "FSecureMalice")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "fsecure"

#-----------------------------------------------------------------------
class CKasperskyMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "KasperskyMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "kaspersky"

#-----------------------------------------------------------------------
class CMcAfeeMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "McAfeeMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "mcafee"

#-----------------------------------------------------------------------
class CYaraMalicePlugin(CMalicePlugin):
  def __init__(self, cfg_parser):
    CMalicePlugin.__init__(self, cfg_parser, "YaraMalice")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.METADATA
    self.container_name = "yara"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CShadowServerMalicePlugin(CMaliceHashPlugin):
  def __init__(self, cfg_parser):
    CMaliceHashPlugin.__init__(self, cfg_parser, "ShadowServerMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "shadow-server"
    self.container_api_endpoint = "lookup"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CVirusTotalMalicePlugin(CMaliceHashPlugin):
  def __init__(self, cfg_parser):
    CMaliceHashPlugin.__init__(self, cfg_parser, "VirusTotalMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "virustotal"
    self.container_api_endpoint = "lookup"
    self.container_run_command_arguments["--api"] = cfg_parser.get(self.name, "API_KEY")
    
  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CNationalSoftwareReferenceLibraryMalicePlugin(CMaliceHashPlugin):
  def __init__(self, cfg_parser):
    CMaliceHashPlugin.__init__(self, cfg_parser, "NationalSoftwareReferenceLibraryMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "nsrl"
    self.container_api_endpoint = "lookup"
    
  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CTrendmicroScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Trendmicro"
    #It seems as fast as kaspersky even faster
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern1 = "\\nfilename=(.*)"
    self.scan_output_pattern2 = "\\nvirus_name=(.*)"

  def scan(self, path):
    if self.scan_output_pattern is None:
      Exception("Not implemented")

    try:
      cmd = self.build_cmd(path)
    except:
      pass
    
    logdir = '/var/log/TrendMicro/SProtectLinux'
    logfile = logdir+'/Virus.' + time.strftime('%Y%m%d') + '.0001'
    call(cmd)

    with open(logfile, 'r') as log:
      output = log.read()
    reset = open(logfile, 'wb') #Clear the log file
    reset.close()

    matches1 = re.findall(self.scan_output_pattern1, output, re.IGNORECASE|re.MULTILINE)
    matches2 = re.findall(self.scan_output_pattern2, output, re.IGNORECASE|re.MULTILINE)
    for i in range(len(matches1)):
      self.results[matches1[i].split(' (')[0]] = matches2[i]

    return len(self.results) > 0
#-----------------------------------------------------------------------

class CComodoScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Comodo"
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern = "(.*) ---\> Found .*, Malware Name is (.*)"
    self.binary_version_pattern = ".*"

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    args.extend(scan_args.replace("$FILE", path).split(" "))
    return args

  def get_binary_version(self):
    try:
      version_file = self.cfg_parser.get(self.name, "BINARY_VERSION")
    except ConfigParser.NoOptionError:
      return "-"

    e = xml.etree.ElementTree.parse(version_file).getroot()
    #<COMODO><AntivirusPro><Configurations><A0><ProductVersion>
    return e[1][4][7][1].text

  def get_engine_data_version(self):
    try:
      version_file = self.cfg_parser.get(self.name, "ENGINE_DATA_VERSION")
    except ConfigParser.NoOptionError:
      return "-"

    update_time = datetime.fromtimestamp(os.path.getmtime(version_file))
    e = xml.etree.ElementTree.parse(version_file).getroot()
    #<COMODO><AntivirusPro><Configurations><A0><Version>
    return e[1][4][7][3].text + " " + str(update_time)

#-----------------------------------------------------------------------
class CCyrenScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Cyren"
    self.speed = AV_SPEED.ULTRA
    self.scan_output_pattern = "Found:(.*)[\s]{3,}(.*)"

  def scan(self, path):
    if self.scan_output_pattern is None:
        Exception("Not implemented")

    try:
        cmd = self.build_cmd(path)
    except: # There is no entry in the *.cfg file for this AV engine?
        pass

    try:
        output = check_output(cmd)
    except CalledProcessError as e:
        output = e.output

    matches = re.findall(self.scan_output_pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      self.results[match[self.file_index].strip()] = match[self.malware_index]
    return len(self.results) > 0

#-----------------------------------------------------------------------
class CKasperskyScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Kaspersky"
    # Considered fast because it requires the daemon to be running.
    # This is why...
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern = r"\d+-\d+-\d+ \d+:\d+:\d+\W(.*)\Wdetected\W(.*)"
    self.scan_output_pattern2 = '(.*)(INFECTED|SUSPICION UDS:|SUSPICION HEUR:|WARNING HEUR:)(.*)'    

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    ver = os.path.basename(scan_path)
    if ver == "kavscanner":
        args.extend(scan_args.split(" "))
        args.append(path)      
    elif ver == "kav":
        args.extend(scan_args.replace("$FILE", path).split(" "))
    return args

  def scan(self, path):
    if self.scan_output_pattern is None:
        Exception("Not implemented")

    try:
        cmd = self.build_cmd(path)
    except: # There is no entry in the *.cfg file for this AV engine?
        pass

    try: # stderr=devnull because kavscanner writes socket info
        with open(os.devnull, "w") as devnull:      
            output = check_output(cmd, stderr=devnull)

    except CalledProcessError as e:
        output = e.output
    ver = os.path.basename(cmd.pop(0))
    if ver == "kavscanner":
        self.file_index = 0
        self.malware_index = 2
        matches = re.findall(self.scan_output_pattern2, output, re.IGNORECASE|re.MULTILINE)
        for match in matches:
          self.results[match[self.file_index].split('\x08')[0].rstrip()] =\
              match[self.malware_index].lstrip().rstrip()
    elif ver == "kav":
        matches = re.findall(self.scan_output_pattern, output, re.IGNORECASE|re.MULTILINE)
        for match in matches:
          self.results[match[self.file_index]] = match[self.malware_index]

    return len(self.results) > 0

#-----------------------------------------------------------------------
class CClamScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "ClamAV"
    self.speed = AV_SPEED.ULTRA
    self.binary_version_pattern = "\d\.\d*.\d*"
    self.engine_data_version_pattern = "[^\/]*\/\w{3}\s.*"

  def scan_one(self, path):
    try:
      tmp = pyclamd.scan_file(path)
      # fix output form e.g {u'/tmp/tmpbspbPz': ('FOUND', 'Eicar-Test-Signature')}
      tmp[path] = tmp[path][1]
      if tmp: self.results.update(tmp)
    except:
      pass

  def scan_dir(self, path):
    for root, dirs, files in os.walk(path, topdown=False):
      for name in files:
        self.scan_one(os.path.join(root, name))
    return len(self.results)

  def scan(self, path):
    parser = self.cfg_parser
    ep = parser.get(self.name, "UNIX_SOCKET")

    clamav_running = False
    retry_counter = 0
    while retry_counter < 5 and not clamav_running:
      try:
        pyclamd.init_unix_socket(filename=ep)
        clamav_running = True
      except pyclamd.ConnectionError as e:
        # clamav-daemon is down
        parser = self.cfg_parser
        try:
          cmd = parser.get(self.name, "RESTART_CMD")
          cmd = cmd.split(" ")
          ouptut = check_output(cmd)
          time.sleep(15)
          print("clamav-daemon restarted. Try {0}. Output {1}".format(retry_counter, ouptut))
          retry_counter += 1
        except ConfigParser.NoOptionError:
          print("clamav-daemon is down and no restart command is configured")
          return False
        except Exception as e:
          print("could not restart clamav-daemon. Error {0}".format(e))
          return False
    
    if os.path.isdir(path):
      self.scan_dir(path)
    else:
      self.scan_one(path)
    return len(self.results) == 0

  def get_binary_version(self):
    parser = self.cfg_parser
    ep = parser.get(self.name, "UNIX_SOCKET")
    pyclamd.init_unix_socket(filename=ep)

    output = pyclamd.version()

    binary_version_pattern = self.binary_version_pattern
    matches = re.findall(binary_version_pattern, output, re.IGNORECASE|re.MULTILINE)
    if len(matches) > 0:
      return " ".join(matches)

    return "-"

  def get_engine_data_version(self):
    parser = self.cfg_parser
    ep = parser.get(self.name, "UNIX_SOCKET")
    pyclamd.init_unix_socket(filename=ep)

    output = pyclamd.version()

    engine_data_version_pattern = self.engine_data_version_pattern
    matches = re.findall(engine_data_version_pattern, output, re.IGNORECASE|re.MULTILINE)
    if len(matches) > 0:
      return ' '.join(matches)

    return "-"

#-----------------------------------------------------------------------
class CFProtScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "F-Prot"
    self.speed = AV_SPEED.ULTRA
    self.scan_output_pattern = "\<(.*)\>\s+(.*)"
    self.file_index = 1
    self.malware_index = 0
    self.binary_version_pattern = "\d*\.\d*\.\d*\.\d*,.*"
    self.engine_data_version_pattern = "(\d*\.\d*\.\d*\.\d{3}$|\d{5,}$)"

#-----------------------------------------------------------------------
class CAviraScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Avira"
    self.speed = AV_SPEED.SLOW
    self.scan_output_pattern = "ALERT: \[(.*)\] (.*) \<\<\<"
    self.file_index = 1
    self.malware_index = 0

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

#-----------------------------------------------------------------------
class CBitDefenderScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "BitDefender"
    self.speed = AV_SPEED.SLOW
    self.scan_output_pattern = "(.*) \s+infected:\s(.*)"
    self.binary_version_pattern = "v\d.\d+ \w+-\w+"
    self.engine_data_version_pattern = "(\w{3}\s\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4}|Signature.*)"

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

# -----------------------------------------------------------------------
class CEsetScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "ESET"
    self.speed = AV_SPEED.MEDIUM

  def scan(self, path):
    os.putenv("LANG", "C")
    cmd = self.build_cmd(path)
    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    scan_output_pattern = 'name="(.*)", threat="(.*)",'
    matches = re.findall(scan_output_pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      malware = match[1][:match[1].find('", ')]
      if malware != "":
        self.results[match[0]] = match[1][:match[1].find('", ')]
    return len(self.results) > 0

# -----------------------------------------------------------------------
class CSophosScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Sophos"
    self.speed = AV_SPEED.MEDIUM
    self.scan_output_pattern = "Virus '(.*)' found in file (.*)"
    self.file_index = 1
    self.malware_index = 0
    self.binary_version_pattern = "Product.*"
    self.engine_data_version_pattern1 = "Engine.*"
    self.engine_data_version_pattern2 = "Virus data.*"
    self.engine_data_version_pattern3 = "\d*\s\w*\s\d*,.*"

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

  def get_binary_version(self):
    try:
      cmd = self.cfg_parser.get(self.name, "BINARY_VERSION").split(' ')
    except ConfigParser.NoOptionError:
      return "-"

    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    binary_version_pattern = self.binary_version_pattern
    matches = re.findall(binary_version_pattern, output, re.IGNORECASE|re.MULTILINE)
    if len(matches) > 0:
      return matches[0].split(": ")[1]

    return "-"

  def get_engine_data_version(self):
    try:
      cmd = self.cfg_parser.get(self.name, "ENGINE_DATA_VERSION").split(' ')
    except ConfigParser.NoOptionError:
      return "-"

    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    res = ["-"]
    engine_data_version_pattern = self.engine_data_version_pattern1
    matches = re.findall(engine_data_version_pattern, output, re.IGNORECASE|re.MULTILINE)
    if len(matches) > 0:
      res.append("Engine: " + matches[0].split(": ")[1])

    engine_data_version_pattern = self.engine_data_version_pattern2
    matches = re.findall(engine_data_version_pattern, output, re.IGNORECASE|re.MULTILINE)
    if len(matches) > 0:
      res.append("Virus data: " +matches[0].split(": ")[1])

    engine_data_version_pattern = self.engine_data_version_pattern3
    matches = re.findall(engine_data_version_pattern, output, re.IGNORECASE|re.MULTILINE)
    if len(matches) > 0:
      res.append("Updated: " + matches[-1])

    if len(res) > 1:
      res.pop(0)

    return ' '.join(res)

# -----------------------------------------------------------------------
class CAvastScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Avast"
    self.speed = AV_SPEED.ULTRA
    self.scan_output_pattern = "(.*)\t(.*)"

  def scan(self, path):
    os.putenv("LANG", "C")
    return CAvScanner.scan(self, path)

# -----------------------------------------------------------------------
class CDrWebScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "DrWeb"
    self.speed = AV_SPEED.SLOW
    self.scan_output_pattern = "\>{0,1}(.*) infected with (.*)"

#-----------------------------------------------------------------------
class CEScanScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "MicroWorld-eScan"
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern = '(.*)\[INFECTED\](.*)'

  def scan(self, path):
    if self.scan_output_pattern is None:
      Exception("Not implemented")
    
    try:
      cmd = self.build_cmd(path)
    except: # There is no entry in the *.cfg file for this AV engine?
      pass
    
    try:
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output
    
    matches = re.findall(self.scan_output_pattern, output, re.IGNORECASE | re.MULTILINE)
    for match in matches:
      self.results[match[self.file_index].rstrip()] = match[self.malware_index]
    return len(self.results) > 0

# -----------------------------------------------------------------------
class CMcAfeeScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "McAfee"
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern = "(.*) \.\.\. Found[:| the]{0,1} (.*) [a-z]+ [\!\!]{0,1}"
    self.scan_output_pattern2 = "(.*) \.\.\. Found [a-z]+ or variant (.*) \!\!"

  def scan(self, path):
    os.putenv("LANG", "C")
    ret = CAvScanner.scan(self, path)

    try:
      old_scan_output_pattern = self.scan_output_pattern
      self.scan_output_pattern = self.scan_output_pattern2
      ret |= CAvScanner.scan(self, path)
    finally:
      self.scan_output_pattern = old_scan_output_pattern

    for match in self.results:
      self.results[match] = self.results[match].strip("the ")

    return ret

# -----------------------------------------------------------------------
class CAvgScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "AVG"
    # Considered fast because it requires the daemon to be running.
    # This is why...
    self.speed = AV_SPEED.ULTRA
    self.scan_output_pattern1 = "\>{0,1}(.*) \s+[a-z]+\s+[a-z]+\s+(.*)"
    self.scan_output_pattern2 = "\>{0,1}(.*) \s+[a-z]+\s+(.*)" #like this:Luhe.Fiha.A

  def scan(self, path):
    cmd = self.build_cmd(path)
    f = NamedTemporaryFile(delete=False)
    f.close()
    fname = f.name

    try:
      cmd.append("-r%s" % fname)
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    output = open(fname, "rb").read()
    os.unlink(fname)

    matches1 = re.findall(self.scan_output_pattern1, output, re.IGNORECASE|re.MULTILINE)
    matches2 = re.findall(self.scan_output_pattern2, output, re.IGNORECASE|re.MULTILINE)
    matches = matches1 +matches2
    for match in matches:
      if match[1] not in ["file"]:
        self.results[match[0].split(':/')[0]] = match[1]
    return len(self.results) > 0

# -----------------------------------------------------------------------
class CIkarusScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "Ikarus"
    self.speed = AV_SPEED.MEDIUM
    # Horrible, isn't it?
    self.scan_output_pattern = "(.*) - Signature \d+ '(.*)' found"

  def scan(self, path):
    cmd = self.build_cmd(path)
    f = NamedTemporaryFile(delete=False)
    f.close()
    fname = f.name

    try:
      cmd.append("-logfile")
      cmd.append(fname)
      output = check_output(cmd)
    except CalledProcessError as e:
      output = e.output

    output = codecs.open(fname, "r", "utf-16").read()
    os.unlink(fname)

    matches = re.findall(self.scan_output_pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      if match[1] not in ["file"]:
        self.results[match[0]] = match[1]
    return len(self.results) > 0

# -----------------------------------------------------------------------
class CFSecureScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "F-Secure"
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern = "(.*): Infected: (.*) \[[a-z]+\]"
# /home/r0x/Downloads/jigsaw: Infected: Trojan.AgentWDCR.GLX [Aquarius]

# -----------------------------------------------------------------------
class CWindowsDefScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "WindowsDefender"
    self.speed = AV_SPEED.FAST
    self.scan_output_pattern = ".* Scanning (.*?)\.{3}.*Threat (.*) identified."
#EngineScanCallback(): Threat Ransom:MSIL/JigsawLocker.A identified
    self.binary_version_pattern = "\d\.\d\.\d*\.\d"

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    args.extend(scan_args.replace("$FILE", path).split(" "))
    return args

  def scan(self, path):
    if self.scan_output_pattern is None:
      Exception("Not implemented")

    try:
      cmd = self.build_cmd(path)
    except: # There is no entry in the *.cfg file for this AV engine?
      pass

    try:
      if cmd:
        output = check_output(cmd, stderr=STDOUT, cwd = os.path.dirname(cmd[0]))
      else:
        output = check_output(cmd, stderr=STDOUT)
    except CalledProcessError as e:
      output = e.output

    scan_output_pattern = self.scan_output_pattern
    matches = re.findall(scan_output_pattern, output, re.IGNORECASE|re.MULTILINE|re.DOTALL)
    for match in matches:
      if match[self.malware_index] == '':
        self.results[match[self.file_index]] = 'Unknown:Win/NameUnknown'
      else:
        self.results[match[self.file_index]] = match[self.malware_index]
    return len(self.results) > 0

# -----------------------------------------------------------------------
class CQuickHealScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.cfg_parser = cfg_parser
    self.name = 'QuickHeal'
    self.speed = AV_SPEED.FAST
    self.file_index = 1
    self.malware_index = 2
    self.scan_output_pattern = '(Scanning : |Archive  : )(.*)\nInfected[\s]+:[\s]+\((.*)\)'    

  def build_cmd(self, path):
    parser = self.cfg_parser
    scan_path = parser.get(self.name, "PATH")
    scan_args = parser.get(self.name, "ARGUMENTS")
    args = [scan_path]
    args.extend(scan_args.replace("$FILE", path).split(" "))
    return args

  def scan(self, path):
    f = NamedTemporaryFile(delete=False)
    f.close()
    fname = f.name

    if self.scan_output_pattern is None:
      Exception("Not implemented")

    try:
      cmd = self.build_cmd(path)
    
    except: # There is no entry in the *.cfg file for this AV engine?
      pass

    try:
      cmd.append("-REPORT=%s" % fname)
      output = check_output(cmd)

    except CalledProcessError as e:
      output = e.output

    output = open(fname, "rb").read()
    os.unlink(fname)
    matches = re.findall(self.scan_output_pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
      self.results[match[self.file_index].rstrip('\r')] = match[self.malware_index]    

    return len(self.results) > 0

# -----------------------------------------------------------------------
class CZavScanner(CAvScanner):
  def __init__(self, cfg_parser):
    CAvScanner.__init__(self, cfg_parser)
    self.name = "ZAV"
    self.speed = AV_SPEED.ULTRA
    self.scan_output_pattern = "(.*): INFECTED \[(.*)\]"

class PullPluginException(Exception):
  pass

class StartPluginException(Exception):
  pass

class CreateNetworkException(Exception):
  pass

# -----------------------------------------------------------------------
class CMultiAV:
  def __init__(self, cfg = "config.cfg", auto_pull = False, start_containers = False):    
    # AV Scanners not available as docker container: 
    # CEsetScanner, CIkarusScanner, CZavScanner, CCyrenScanner,  CQuickHealScanner, CTrendmicroScanner

    self.engines = [CFileInfo, CWindowsDefenderMalicePlugin,
                    CSophosMalicePlugin, CAvastMalicePlugin, CAvgMalicePlugin,
                    CBitDefenderMalicePlugin, CClamAVMalicePlugin, CComodoMalicePlugin,
                    CDrWebMalicePlugin, CEScanMalicePlugin, CFProtMalicePlugin,
                    CFSecureMalicePlugin, CKasperskyMalicePlugin, CMcAfeeMalicePlugin,
                    CYaraMalicePlugin, CShadowServerMalicePlugin, CVirusTotalMalicePlugin,
                    CNationalSoftwareReferenceLibraryMalicePlugin, CPEScanMalicePlugin, CFlossMalicePlugin]

    self.processes = cpu_count()
    self.cfg = cfg
    self.read_config()
    self.updateMutex = RWLock()

    # startup checks, disabled per default
    if auto_pull:
      print("Checking if all plugins are pulled and pulling them if required...")
      if not self.pull_plugin_containers():
        raise PullPluginException("Plugin container pulling failed!")

      print("All plugins pulled!")

    if start_containers:
      if not self.is_no_internet_network_existing():
        print("No-Internet network is not existing. Creating it now...")
        if not self.create_no_internet_network():
          raise CreateNetworkException("Could not create no-internet-network!")
        print("No-Internet network created")

      if not self.is_internet_network_existing():
        print("Internet network is not existing. Creating it now...")
        if not self.create_internet_network():
          raise CreateNetworkException("Could not create internet-network!")
        print("Internet network created")

      print("Checking if all plugins are running and staring them if required...")

      if not self.start_containers():
        raise StartPluginException("Plugin container pulling failed!")

      print("All plugins started!")
    

  def read_config(self):
    parser = ConfigParser.SafeConfigParser()
    parser.optionxform = str
    parser.read(self.cfg)
    self.parser = parser

  def exec_func_multi_processes(self, object_list, func, args = None):
    q = Queue()
    objects = object_list
    running = []
    results = {}

    while len(objects) > 0 or len(running) > 0:
      if len(objects) > 0 and len(running) < self.processes:
        obj = objects.pop()
        
        args_combined = (obj, results, q)
        if args != None: args_combined += args

        p = Process(target=func, args=args_combined)
        p.start()
        running.append(p)

      # check if processes is still running
      newrunning = []
      for p in list(running):
        p.join(0.1)
        if p.is_alive():
          newrunning.append(p)
      running = newrunning

    results = {}
    print("update dict from queue...")
    while not q.empty():
      results.update(q.get())

    print("update dict from queue complete!")
    return results

  def is_no_internet_network_existing(self):
    cmd = "docker network ls"
    output = str(check_output(cmd.split(" ")))

    return DOCKER_NETWORK_NO_INTERNET_NAME in output

  def create_no_internet_network(self):
    network_address = self.parser.get("MULTIAV", "DOCKER_NETWORK_NO_INTERNET")
    cmd = "docker network create --driver bridge --internal --subnet={1}/24 {0}".format(DOCKER_NETWORK_NO_INTERNET_NAME, network_address)
    check_output(cmd.split(" "))

    return self.is_no_internet_network_existing()

  def is_internet_network_existing(self):
    cmd = "docker network ls"
    output = str(check_output(cmd.split(" ")))

    return DOCKER_NETWORK_INTERNET_NAME in output

  def create_internet_network(self):
    network_address = self.parser.get("MULTIAV", "DOCKER_NETWORK_INTERNET")
    cmd = "docker network create --driver bridge --subnet={1}/24 {0}".format(DOCKER_NETWORK_INTERNET_NAME, network_address)
    check_output(cmd.split(" "))

    return self.is_internet_network_existing()

  def scan(self, path, max_speed=AV_SPEED.ALL, allow_internet=False):
    if not os.path.exists(path):
      raise Exception("Path not found")

    if self.processes > 1:
      return self.multi_scan(path, max_speed, allow_internet)
    else:
      return self.single_scan(path, max_speed, allow_internet)
    
  def multi_scan(self, path, max_speed, allow_internet=False):
    engines = list(self.engines)
    return self.exec_func_multi_processes(random.sample(engines, len(engines)), self.scan_one, (path, max_speed, allow_internet))

  def single_scan(self, path, max_speed=AV_SPEED.ALL, allow_internet=False):
    results = {PLUGIN_TYPE.AV: {}, PLUGIN_TYPE.METADATA: {}}
    for av_engine in self.engines:
      results.update(self.scan_one(av_engine, results, path=path, max_speed=max_speed, allow_internet=allow_internet))
    return results

  def scan_one(self, av_engine, results, q=None, path=None, max_speed = None, allow_internet=False):
    with self.updateMutex.reader_lock:
      av = av_engine(self.parser)
      if av.is_disabled():
        return results

      if av.container_requires_internet == True and not allow_internet:
        print("[{0}] Skipping. Internet policy doesn't match".format(av.name))
        return results
      
      if max_speed == None or av.speed.value <= max_speed.value:
        print("[{0}] Starting scan".format(av.name))
        scan_success = av.scan(path)
        
        result = av.results
        result["plugin_type"] = av.plugin_type
        result["speed"] = av.speed.name

        if av.plugin_type == PLUGIN_TYPE.LEGACY:
          binary_version = av.get_binary_version()
          engine_version = av.get_engine_data_version()

          result["infected"] = result != {}
          result["engine"] = binary_version + " " + engine_version
          result["updated"] = "-"
          result["has_internet"] = True
          results[av.name] = result
        else:
          result["has_internet"] = av.container_requires_internet
          results[av.name] = result
          
        if scan_success:
          print("[{0}] Scan complete.".format(av.name))
        else:
          print("[{0}] Scan failed".format(av.name))
      else:
        print("[{0}] Skipping scan. Too slow! AV: {1} Max: {2}".format(av.name, av.speed.value, max_speed.value))

      if q is not None:
        q.put(results)
      
      print("[{0}] Scan routine complete.".format(av.name))
      return True

  def scan_buffer(self, buf, max_speed=AV_SPEED.ALL, allow_internet=False):
    f = NamedTemporaryFile(delete=False)
    f.write(buf)
    f.close()

    fname = f.name
    os.chmod(f.name, 436)

    try:
      ret = self.scan(fname, max_speed, allow_internet)
    finally:
      print("unlinking file")
      os.unlink(fname)
      print("unlinking complete")

    return ret
  
  def get_scanners(self):
    scanners = {}
    for av in list(self.engines):
      if av.is_disabled():
        continue
    
      scanners[av.name] = {
        'signature_version': av.get_signature_version(),
        'plugin_type': av.plugin_type,
        'has_internet': av.container_requires_internet
      }
    
    return scanners

  def update_one(self, av_engine, results, q = None):
    result = ""
    old_signature_version = "-"
    av = av_engine(self.parser)

    try:
      if av.is_disabled():
          return results

      print("[{0}] Starting update".format(av.name))

      old_signature_version = av.get_signature_version()

      result = av.update()

      print("[{0}] updated!".format(av.name))
    except Exception as e:
      print("[{0}] update failed! Exception: {1}".format(av.name, e))
    
    results[av.name] = {
      'status': result,
      'old_signature_version': old_signature_version,
      'signature_version': av.get_signature_version(),
      'plugin_type': av.plugin_type,
      'has_internet': av.container_requires_internet,
      'speed': av.speed.name
      }

    if q is not None:
      q.put(results)

    return results

  def update(self):
    # TODO Implement handing for singe core prcessors => no mt overhead
    with self.updateMutex.writer_lock:
      return self.exec_func_multi_processes(list(self.engines), self.update_one)

  def pull_one(self, plugin, results, q = None):
    result = False
    p = plugin(self.parser)

    try:
      if p.is_disabled():
          return results

      if not isinstance(p, CMalicePlugin):
          print("Plugin {0} is not a docker plugin. Skipping...".format(p.name))
          return results

      if not p.pull_container():
        raise Exception("pull_container() returned False")

      result = True
    except Exception as e:
      print("Pull of plugin {0} failed! Exception: {1}".format(p.name, e))
    
    results[p.name] = result

    if q is not None:
      q.put(results)

    return results

  def pull_plugin_containers(self):
    # TODO Implement handing for singe core prcessors => no mt overhead
    results = self.exec_func_multi_processes(list(self.engines), self.pull_one)
    for plugin in results:
      if not results[plugin]:
        return False
    
    return True

  def start_one(self, plugin, results, q = None):
    result = False
    p = plugin(self.parser)

    try:
      if p.is_disabled():
          return results

      if not isinstance(p, CMalicePlugin):
          return results
      
      if not p.is_container_running():
        if not p.start_container():
          raise Exception("start_container() returned False")
        
        print("[{0}] Started!".format(p.name))

      result = True
    except Exception as e:
      print("[{0}] Start failed! Exception: {1}".format(p.name, e))
    
    results[p.name] = result

    if q is not None:
      q.put(results)

    return results

  def start_containers(self):
    # TODO Implement handing for singe core prcessors => no mt overhead
    results = self.exec_func_multi_processes(list(self.engines), self.start_one)
    for plugin in results:
      if not results[plugin]:
        return False
    
    return True
