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
  __order__ = 'ALL ULTRA FAST MEDIUM SLOW'
  ALL = 3  # Run only when all engines must be executed
  SLOW = 2
  MEDIUM = 1
  FAST = 0
  ULTRA = -1

class PLUGIN_TYPE(OrderedEnum):
  #LEGACY = 0
  AV = 1
  METADATA = 2
  INTEL = 3
  FILE_FORMATS = 4

DOCKER_NETWORK_NO_INTERNET_NAME = "multiav-no-internet-bridge"
DOCKER_NETWORK_INTERNET_NAME = "multiav-internet-bridge"

#-----------------------------------------------------------------------
class CDockerAvScanner():
  def __init__(self, cfg_parser, name):
    self.cfg_parser = cfg_parser
    self.name = name
    self.speed = AV_SPEED.SLOW
    self.plugin_type = None
    self.results = {}
    self.container_name = None
    self.plugin_id = cfg_parser.get(self.name, "PLUGIN_ID")
    self.docker_network_no_internet = self.cfg_parser.get("MULTIAV", "DOCKER_NETWORK_NO_INTERNET").split(".") #[10,192,212,0]
    self.docker_network_internet = self.cfg_parser.get("MULTIAV", "DOCKER_NETWORK_INTERNET").split(".") #[10,168,137,0]
    self.container_api_endpoint = "scan"
    self.container_api_sample_parameter_name = "malware"
    self.container_requires_internet = int(self.get_config_value(self.name, "ENABLE_INTERNET_ACCESS", 0)) == 1
    self.container_api_host = self.get_api_host()
    self.container_api_port = 3993
    self.container_build_url_override = self.get_config_value(self.name, "DOCKER_BUILD_URL_OVERRIDE", None)
    self.container_run_command_arguments = dict()
    self.container_run_docker_parameters = dict()
    self.container_build_params = dict()
  
  def get_config_value(self, name, variable, default):
    if self.cfg_parser.has_option(name, variable):
      return self.cfg_parser.get(self.name, variable)
    return default

  def is_disabled(self):
    try:
      self.cfg_parser.get(self.name, "DISABLED")
      return True
    except:
      return False

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
class CDockerHashLookupService(CDockerAvScanner):
  def __init__(self, cfg_parser, name):
    CDockerAvScanner.__init__(self, cfg_parser, name)
  
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
class CFileInfo(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FileInfoMalice")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.METADATA
    self.container_name = "fileinfo"
  
  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CPEScanMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "PEScanMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.FILE_FORMATS
    self.container_name = "pescan"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CFlossMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FlossMalice")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.FILE_FORMATS
    self.container_name = "floss"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
# Update and download servers not reachable anymore :/
'''class CZonerMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "ZonerMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "zoner"
    self.container_api_port = cfg_parser.get(self.name, "API_PORT")
    self.container_restart_after_query = cfg_parser.get(self.name, "RESTART_CONTAINER_AFTER_QUERY")
    self.container_enviroment_variables["ZONE_KEY"] = cfg_parser.get(self.name, "LICENSE_KEY")'''

#-----------------------------------------------------------------------
class CWindowsDefenderMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "WindowsDefenderMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "windows-defender"
    self.container_run_docker_parameters["--security-opt"] = "seccomp=seccomp.json"

#-----------------------------------------------------------------------
class CSophosMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "SophosMalice")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "sophos"

#-----------------------------------------------------------------------
class CAvastMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "AvastMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avast"

  def update(self):
    return "skipped"

#-----------------------------------------------------------------------
class CAvgMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "AvgMalice")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "avg"

#-----------------------------------------------------------------------
class CBitDefenderMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "BitDefenderMalice")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "bitdefender"
    self.container_build_params["BDKEY"] = cfg_parser.get(self.name, "LICENSE_KEY")

#-----------------------------------------------------------------------
class CClamAVMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "ClamAVMalice")
    self.speed = AV_SPEED.ULTRA
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "clamav"

#-----------------------------------------------------------------------
class CComodoMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "ComodoMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "comodo"

#-----------------------------------------------------------------------
class CDrWebMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "DrWebMalice")
    self.speed = AV_SPEED.SLOW
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "drweb"

#-----------------------------------------------------------------------
class CEScanMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "EScanMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "escan"

#-----------------------------------------------------------------------
class CFProtMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FProtMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "fprot"

#-----------------------------------------------------------------------
class CFSecureMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "FSecureMalice")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "fsecure"

#-----------------------------------------------------------------------
class CKasperskyMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "KasperskyMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "kaspersky"

#-----------------------------------------------------------------------
class CMcAfeeMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "McAfeeMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.AV
    self.container_name = "mcafee"

#-----------------------------------------------------------------------
class CYaraMalicePlugin(CDockerAvScanner):
  def __init__(self, cfg_parser):
    CDockerAvScanner.__init__(self, cfg_parser, "YaraMalice")
    self.speed = AV_SPEED.MEDIUM
    self.plugin_type = PLUGIN_TYPE.METADATA
    self.container_name = "yara"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CShadowServerMalicePlugin(CDockerHashLookupService):
  def __init__(self, cfg_parser):
    CDockerHashLookupService.__init__(self, cfg_parser, "ShadowServerMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "shadow-server"
    self.container_api_endpoint = "lookup"

  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CVirusTotalMalicePlugin(CDockerHashLookupService):
  def __init__(self, cfg_parser):
    CDockerHashLookupService.__init__(self, cfg_parser, "VirusTotalMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "virustotal"
    self.container_api_endpoint = "lookup"
    self.container_run_command_arguments["--api"] = cfg_parser.get(self.name, "API_KEY")
    
  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class CNationalSoftwareReferenceLibraryMalicePlugin(CDockerHashLookupService):
  def __init__(self, cfg_parser):
    CDockerHashLookupService.__init__(self, cfg_parser, "NationalSoftwareReferenceLibraryMalice")
    self.speed = AV_SPEED.FAST
    self.plugin_type = PLUGIN_TYPE.INTEL
    self.container_name = "nsrl"
    self.container_api_endpoint = "lookup"
    
  def update(self):
    return "not supported"

#-----------------------------------------------------------------------
class PullPluginException(Exception):
  pass

#-----------------------------------------------------------------------
class StartPluginException(Exception):
  pass

#-----------------------------------------------------------------------
class CreateNetworkException(Exception):
  pass

# -----------------------------------------------------------------------
class CMultiAV:
  def __init__(self, cfg = "config.cfg", auto_pull = False, start_containers = False):
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
