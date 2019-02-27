#!/usr/bin/env python

from multiav.core import CMultiAV, PullPluginException, StartPluginException, CreateNetworkException
from multiav.webapi import app

if __name__ == "__main__": 
  try:
    cav = CMultiAV("config.cfg", auto_pull=True, start_containers=True)
  except PullPluginException as e:
    print(e)
    exit(2)
  except StartPluginException as e:
    print(e)
    exit(3)
  except CreateNetworkException as e:
    print(e)
    exit(4)
  finally:
    try:
      del cav
    except:
      pass

  app.run()
