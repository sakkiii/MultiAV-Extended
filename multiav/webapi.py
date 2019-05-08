import os
import sys
import json
import time
import datetime
import web

from rwlock import RWLock
from hashlib import md5, sha1, sha256
from itertools import groupby
from multiprocessing import cpu_count

from multiav.core import CMultiAV, AV_SPEED, PLUGIN_TYPE
from multiav.enumencoder import EnumEncoder
from multiav.scannerstrategy import JustRunLocalDockerStrategy, LimitedLocalDockerStrategy, AutoScaleDockerStrategy
from multiav.exceptions import PullPluginException, StartPluginException, CreateNetworkException

urls = (
    '/', 'index',
    '/upload', 'upload',
    '/api/upload', 'api_upload',
    '/api/search', 'api_search',
    '/api/report', 'api_report',
    '/about', 'about',
    '/last', 'last',
    '/search', 'search',
    '/export/csv', 'export_csv',
    '/update', 'update',
    '/system', 'system'
)

app = web.application(urls, globals())
ROOT_PATH = os.path.dirname(__file__)
CURRENT_PATH = os.getcwd()
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

# -----------------------------------------------------------------------
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class CDbSamples():
  def __init__(self):
    self.db = web.database(dbn='sqlite', db='multiav.db')
    self.db.printing = False
    self.create_schema()

    self.reports_lock = RWLock()

  def __enter__(self):
      return self

  def __exit__(self, exc_type, exc_value, traceback):
      self.db._unload_context(self.db._getctx())
  
  def create_schema(self):
    with self.db.transaction():
      try:
        self.db.query("""create table if not exists samples(
                                                id integer not null primary key autoincrement,
                                                name text,
                                                md5 text unique,
                                                sha1 text unique,
                                                sha256 text unique,
                                                size text)""")
        self.db.query("""create table if not exists reports(
                                                id integer not null primary key autoincrement,
                                                sample_id integer,
                                                infected integer,
                                                start_date text,
                                                end_date text,
                                                FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE)""")
        self.db.query("""create table if not exists scanners(
                                                id integer not null primary key autoincrement,
                                                name text,
                                                plugin_type integer,
                                                signature_version text,
                                                engine_version text,
                                                has_internet integer,
                                                speed text)""")
        self.db.query("""create table if not exists results(
                                                id integer not null primary key autoincrement,
                                                report_id integer,
                                                scanner_id integer,
                                                scanning integer,
                                                queued integer,
                                                result text,
                                                FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE,
                                                FOREIGN KEY(scanner_id) REFERENCES scanners(id) ON DELETE CASCADE)""")
      except:
        print("Error:", sys.exc_info())[1]

  def finish_sample_report(self, report_id):
    with self.reports_lock.writer_lock:
      try:
        with self.db.transaction():
          '''where = 'report_id like $report_id'
          rows = self.db.select("results", where=where, vars={'report_id': report_id}).list()

          # calculate infected percentage
          result_clean = 0
          for row in rows:
            result = json.loads(row['result'])
            if not result["infected"]:
              result_clean += 1

          if result_clean == 0:
            infected = 0
          else:
            infected = ( result_clean / len(rows) ) * 100
          print("webapi: finish_sample_report infected: {0}%".format(infected))'''
          
          where = 'id like $report_id'
          self.db.update("reports", vars={'report_id': report_id}, where=where, end_date=time.asctime())
      except Exception as e:
        print("finish_sample_report exception:")
        print(e)

  def create_sample_report(self, name, buf):
    # default values
    infected = -1

    # calculate file properties
    md5_hash = md5(buf).hexdigest()
    sha1_hash = sha1(buf).hexdigest()
    sha256_hash = sha256(buf).hexdigest()
    size = len(buf)

    try:
      with self.reports_lock.writer_lock:
        with self.db.transaction():
          # insert sample if not exists
          query = "INSERT INTO samples(name, md5, sha1, sha256, size) SELECT $name, $md5, $sha1, $sha256, $size WHERE NOT EXISTS(SELECT 1 FROM samples WHERE sha256 = $sha256)"
          self.db.query(query, vars={"name":name, "md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash, "size": size})
          
          # get sample id
          res = self.search_sample_by_hash(sha256_hash)
          sample_id = res[0].id

          # insert report with sample_id
          report_id = self.db.insert('reports', infected=infected, start_date=time.asctime(), end_date=None, sample_id=sample_id)

          return report_id
    except:
      print("Error:", sys.exc_info()[1], md5_hash, sha1_hash, sha256_hash)
      return -1
  
  def add_scan_result(self, report_id, result, queued, scanning):
    # result e.g. {u'engine': u'0.100.2', u'updated': u'20190219', u'name': u'ClamAVMalice', u'has_internet': False, u'infected': False, u'result': u'', u'speed': u'ULTRA', u'plugin_type': u'AV'}
    try:
      with self.reports_lock.writer_lock:
        with self.db.transaction():
          scanners = self.get_scanner(result["name"]).list()

          if len(scanners) == 0:
            scanner_id = self.insert_scanner(result["name"], int(result["plugin_type"]), result["has_internet"], int(result["speed"]), result["updated"], result["engine"])
          else:
            scanner_id = scanners[0]["id"]
          
          # skip insert if already exists
          where = 'report_id == $report_id AND scanner_id == $scanner_id'
          if len(list(self.db.select('results', where=where, vars={'report_id': report_id, 'scanner_id': scanner_id}))) != 0:
            return

          self.db.insert('results', report_id=report_id, scanner_id=scanner_id, queued=queued, scanning=scanning, result=json.dumps(result, cls=EnumEncoder))
    except Exception as e:
      print(e)

  def update_scan_result(self, report_id, result, queued, scanning):
    try:
      with self.reports_lock.writer_lock:
        with self.db.transaction():
          scanners = self.get_scanner(result["name"]).list()
          
          if len(scanners) == 0:
            scanner_id = self.insert_scanner(result["name"], int(result["plugin_type"]), result["has_internet"], int(result["speed"]), result["updated"], result["engine"])
          else:
            scanner_id = scanners[0]["id"]

          where = 'report_id == $report_id AND scanner_id == $scanner_id'
          res = self.db.update('results', where=where, vars={'report_id': report_id, 'scanner_id': scanner_id}, queued=queued, scanning=scanning, result=json.dumps(result, cls=EnumEncoder))
        
          #print("webapi: update_scan_result res: {0} report_id: {1} scanner_name: {2} scanner_id: {3}".format(res, report_id, result["name"], scanner_id))

          if res == 0:
            # no row updated, probably update called prior to add => it's a race
            self.add_scan_result(report_id, result, queued, scanning)
        
    except Exception as e:
      print("webapi: update_scan_result exception! report_id: {0} result: {1}".format(report_id, result))
      print(e)

  def search_results_by_report_id(self, report_id):
    with self.reports_lock.reader_lock:
      with self.db.transaction():
        where = 'report_id == $report_id'
        rows = self.db.select("results", where=where, vars={'report_id': report_id}).list()

    results = []
    for row in rows:
      result = json.loads(row["result"])
      result["queued"] = row["queued"]
      result["scanning"] = row["scanning"]
      results.append(result)

    return results

  def search_report_by_id(self, report_id):
    with self.reports_lock.reader_lock:
      with self.db.transaction():
        query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.start_date,reports.end_date " \
                "FROM samples " \
                "LEFT JOIN reports ON samples.id = reports.sample_id " \
                "WHERE report_id = $report_id"
        rows = self.db.query(query, vars={"report_id": report_id}).list()
        for row in rows:
          row["result"] = self.search_results_by_report_id(report_id)
        return rows

  def search_sample_by_hash(self, file_hash):
    with self.reports_lock.reader_lock:
      with self.db.transaction():
        query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.start_date,reports.end_date,results.result " \
                "FROM samples " \
                "LEFT JOIN reports ON samples.id = reports.sample_id " \
                "LEFT JOIN results ON results.report_id = reports.id " \
                "WHERE md5=$hash OR sha1=$hash OR sha256=$hash OR samples.name like $hash"
        rows = self.db.query(query, vars={"hash":file_hash})
        return rows

  def search_samples(self, value):
    with self.reports_lock.reader_lock:
      with self.db.transaction():
        if value is None:
          query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.start_date,reports.end_date " \
                  "FROM samples " \
                  "LEFT JOIN reports ON samples.id = reports.sample_id "
          rows = self.db.query(query).list()
        else:
          query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.start_date,reports.end_date "\
                  "FROM samples " \
                  "LEFT JOIN reports ON samples.id = reports.sample_id " \
                  "WHERE md5=$val OR sha1=$val OR sha256=$val OR samples.name like $val"
          rows = self.db.query(query, vars={"val":value}).list()

        for row in rows:
          row["result"] = self.search_results_by_report_id(row["report_id"])
        return rows
  
  def count_reports(self):
    with self.reports_lock.reader_lock:
      with self.db.transaction():
        query = "SELECT COUNT(*) FROM reports"
        return int(list(self.db.query(query))[0]["COUNT(*)"])

  def last_samples(self, limit, page):
    with self.reports_lock.reader_lock:
      with self.db.transaction():
        offset = limit * page
        query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.start_date,reports.end_date " \
                "FROM samples "\
                "LEFT JOIN reports ON samples.id = reports.sample_id " \
                "ORDER BY reports.id desc " \
                "LIMIT $limit " \
                "OFFSET $offset"
        rows = self.db.query(query, vars={'limit': limit, 'offset': offset}).list()
        for row in rows:
          row["result"] = self.search_results_by_report_id(row["report_id"])
        return rows

  def get_scanners(self):
    with self.db.transaction():
      rows = self.db.select("scanners")
      return rows

  def get_scanner(self, name):
    with self.db.transaction():
      where = 'name like $name'
      rows = self.db.select("scanners", where=where, vars={'name': name})
      return rows

  def insert_scanner(self, name, plugin_type, has_internet, speed, signature_version, engine_version):
    if isinstance(plugin_type, int):
      plugin_type_value = plugin_type
    else:
      plugin_type_value = plugin_type.value

    has_internet = 1 if has_internet == True else 0
    
    try:
      with self.db.transaction():
        row = self.get_scanner(name)
        if len(row.list()) == 0:
          row = self.db.insert("scanners",name=name, plugin_type=plugin_type_value, has_internet=has_internet, speed=speed, \
                                signature_version=str(signature_version), engine_version=str(engine_version))
        
        return row
    except Exception as e:
      print("Exception insert_scanner")
      print(locals())
      print(e)
      return False
    
  def update_scanner(self, name, plugin_type, has_internet, speed, signature_version, engine_version=None):
    # prevent unknown type errors
    if isinstance(plugin_type, int):
      plugin_type_value = plugin_type
    else:
      plugin_type_value = plugin_type.value
    
    has_internet = 1 if has_internet == True else 0

    # store data
    where='name = $name'

    try:
      with self.db.transaction():
        if engine_version is not None:
          updated_rows = self.db.update("scanners", vars={"name": name}, where=where, \
                              plugin_type=plugin_type_value, has_internet=has_internet, speed=speed, \
                              signature_version=str(signature_version), engine_version=str(engine_version))
        else:
          updated_rows = self.db.update("scanners", vars={"name": name}, where=where, \
                              plugin_type=plugin_type_value, has_internet=has_internet, speed=speed, \
                              signature_version=str(signature_version))
    except Exception as e:
      print("Exception update_scanner")
      print(locals())
      print(e)

    # insert new scanner if none existed)
    if updated_rows == 0:
      self.insert_scanner(name, plugin_type, has_internet, signature_version, speed, \
        engine_version if engine_version is not None else "-")

    return updated_rows

# -----------------------------------------------------------------------
# MultiAV Instance
try:
  overprovisioning_multiplyer=1
  config_name = "config.cfg"
  scanner_strategy = AutoScaleDockerStrategy(config_name, min_machines=2, max_machines = 5, max_containers_per_machine = cpu_count() * overprovisioning_multiplyer, max_scans_per_container = 1)
  CAV = CMultiAV(scanner_strategy, config_name, auto_start=True, auto_pull=True)
except PullPluginException as e:
  print(e)
  exit(2)
except StartPluginException as e:
  print(e)
  exit(3)
except CreateNetworkException as e:
  print(e)
  exit(4)

if not os.path.isdir(os.path.join(CURRENT_PATH, 'static')):
    raise Exception('runserver.py must be run in the directory {0}'.format(ROOT_PATH))

# -----------------------------------------------------------------------
def convert_result_rows_to_ui_datastructure(rows):
  result_array = []
  for scan_result in rows:
        # calculate additionally used data and setup result object
        result = {
          "start_date": datetime.datetime.strptime(scan_result['start_date'], '%a %b %d %H:%M:%S %Y') if scan_result['start_date'] != None else None,
          "end_date": datetime.datetime.strptime(scan_result['end_date'], '%a %b %d %H:%M:%S %Y') if scan_result['end_date'] != None else None,
          "hashes": {
            "md5": scan_result['md5'],
            "sha1": scan_result['sha1'],
            "sha256": scan_result['sha256']
          },
          "file": {
            "name": scan_result['name'],
            "size": scan_result['size'],
          },
          "statistics": {
            "engine_count": 0,
            "engine_detected_count":0
          }
        }
        
        for plugin_type in PLUGIN_TYPE:
          result[plugin_type] = {}

        # sort results by plugin_type
        for res_obj in scan_result['result']:
          # store result
          plugin_type = PLUGIN_TYPE(res_obj["plugin_type"])
          result[plugin_type][res_obj["name"]] = res_obj

          if plugin_type == PLUGIN_TYPE.AV:
            # update statistics
            has_error, error = result_has_error(res_obj)
            if not has_error:
              result["statistics"]["engine_count"] += 1

              if res_obj["infected"]:
                result["statistics"]["engine_detected_count"] += 1

        if result["statistics"]["engine_count"] != 0:
          result["statistics"]["infected"] = int(float(result["statistics"]["engine_detected_count"]) / float(result["statistics"]["engine_count"]) * 100)
        else:
          result["statistics"]["infected"] = 0
        result_array.append(result)

  return result_array

def plugin_type_to_string(plugin_type):
  return PLUGIN_TYPE(plugin_type).name.lower()

def result_has_error(result):
  if not "error" in result:
    return (False, None)
  
  if result["error"] == "":
    return (False, None)
  
  return (True, result["error"])

# -----------------------------------------------------------------------
class last:
  def GET(self):
    try:
      i = web.input()
      if 'limit' in i:
        limit = int(i['limit'])
      else:
        limit = 20
      
      if 'page' in i:
        page = int(i['page']) - 1
        if page < 0:
          page = 0
      else:
        page = 0
      
      with CDbSamples() as db:
        rows = db.last_samples(limit, page)
      
      result_array = convert_result_rows_to_ui_datastructure(rows)

      # calculate the pagination stuff
      total_reports_count = db.count_reports()
      total_pages = int(total_reports_count / limit)

      nextpage = page + 1
      if nextpage > total_pages:
        nextpage = total_pages
        print(nextpage)

      pagination = {
        "backpage": 0,
        "backpage_disabled": False,
        "currentpage": page + 1,
        "nextpage": nextpage,
        "nextpage_disabled": False
      }

      pagenumbers = {0}
      if page > 1:
        pagenumbers.add(page)
          
      if total_pages > 1 and total_pages != page + 1:
        pagenumbers.add(total_pages - 1)
      else:
        pagination["nextpage_disabled"] = True
      

      # show next 2 page numbers
      max_pages_to_add = 2
      added_pages = 0
      for i in range(page,total_pages):
        if added_pages > max_pages_to_add:
          break
        pagenumbers.add(i)
        added_pages += 1

      # show last 2 page numbers
      added_pages = 0
      for i in range(page - max_pages_to_add,page):
        if added_pages > max_pages_to_add:
          break
        
        if i <= 0:
          continue

        pagenumbers.add(i)
        added_pages += 1

      # increase all added numbers by one => ui => page 0 = page 1
      pagination["pages"] = sorted(map(lambda page: page + 1, pagenumbers))

      if page + 1 == 1:
        pagination["backpage"] = 1
        pagination["backpage_disabled"] = True
      else:
        # page + 1 - 1 = page
        pagination["backpage"] = page

      render = web.template.render(TEMPLATE_PATH, globals={ 
        "type": type, 
        "map": map,
        "sorted": sorted, 
        "result_has_error": result_has_error, 
        "PLUGIN_TYPE": PLUGIN_TYPE })
      return render.last(result_array, pagination)
    except Exception as e:
      return '{exception: {0}}'.format(e)


# -----------------------------------------------------------------------
class search:
  def GET(self):
    # support search using GET parameters
    i = web.input(q="", id="")
    if i["q"] != "" or i["id"] != "":
      return self.POST()
    
    # show search mask
    render = web.template.render(TEMPLATE_PATH)
    return render.search(None)

  def POST(self):
    render = web.template.render(TEMPLATE_PATH, globals={ 
      "type": type,
      "map": map,
      "sorted": sorted, 
      "result_has_error": result_has_error, 
      "plugin_type_to_string": plugin_type_to_string, 
      "PLUGIN_TYPE": PLUGIN_TYPE })

    # Get querys from params
    querylist = []
    search = None

    with CDbSamples() as db:
      i = web.input(q="", id="")
      if i["q"] != "":
        querylist = i["q"].split(',')
        search = db.search_samples
      elif i["id"] != "":
        querylist = i["id"].split(',')
        search = db.search_report_by_id
      else:
        return render.search(None)

    # perform search
    result_array = []

    for query in list(set(querylist)):
      rows = search(query)
      result_array += convert_result_rows_to_ui_datastructure(rows)

    if len(result_array) == 0:
      return render.search("No match")

    return render.search_results(result_array, ','.join(querylist))


# -----------------------------------------------------------------------
class export_csv:
  def process_query_result(self, rows, headers):
    data = []
    for row in rows:
        data_row = {}
        result = json.loads(row['result'])

        for key, value in result.iteritems():
          if value["plugin_type"] == PLUGIN_TYPE.AV:
            version = value['engine'].replace('\n', ' ').replace('\r', '') + \
                      ' ' + \
                      value['updated'].replace('\n', ' ').replace('\r', '')

            has_error, error = result_has_error(value)

            if has_error:
              result = error
            else:
              # e.g. fsecure' returning results of 2 engines
              if "results" in value:
                result = " ".join(value['results'].values())
              else:
                result = value['result'] if value['result'] != "" else 'clean'

            data_row[key] = result
            data_row[key + '-version'] = version

          else:
            data_row[key] = json.dumps(value, cls=EnumEncoder)
        
        for key in headers:
          data_row[key] = row[key]

        data.append(data_row)
    return data
  
  def GET(self):
    headers = ['name', 'md5', 'sha1', 'sha256', 'date']
    data = []

    with CDbSamples() as db:
      # get querys
      i = web.input(q="", l="", p="")
      if i["q"] != "":    
        querys = list(set(i["q"].split(',')))

        # execute search   
        for query in querys:
          rows = db.search_samples(query)
          data += self.process_query_result(rows, headers)

      elif i["l"] != "" and i["p"] != "":
        limit = int(i["l"])
        page = int(i["p"])
        rows = db.last_samples(limit, page)
        data += self.process_query_result(rows, headers)

      else:
        rows = db.search_samples(None)
        data += self.process_query_result(rows, headers)


    # generate headers
    engines = set()
    for row in data:
      engines.update(row)
    engines = list(engines - set(headers))
    engines.sort()

    # return & generate csv
    csv = []
    csv.append(';'.join(headers + engines))
    for report in data:
      row = []
      for key in headers:
        if key in report:
          row.append(report[key])
        else:
          row.append('n/a')
      
      for key in engines:
        if key in report:
          row.append(report[key])
        else:
          row.append('not scanned')
      
      csv.append(';'.join(row))

    web.header('Content-Type', 'text/csv')
    web.header('Content-disposition', 'attachment; filename=multi-av-export.csv')

    return '\n'.join(csv)

# -----------------------------------------------------------------------
class index:
  def GET(self):
    with CDbSamples() as db:
      db_scanners = db.get_scanners().list()

    for scanner in db_scanners:
      scanner["speed"] = AV_SPEED(int(scanner["speed"])).name.lower().capitalize()
      scanner["plugin_type"] = PLUGIN_TYPE(int(scanner["plugin_type"])).name.lower().capitalize()

    render = web.template.render(TEMPLATE_PATH, globals={"sorted": sorted})
    return render.index(db_scanners, cpu_count(), AV_SPEED)


# -----------------------------------------------------------------------
class about:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    return render.about()


# -----------------------------------------------------------------------
class api_report:
  def GET(self):
    return self.POST()

  def POST(self):
    i = web.input(id="")
    if i["id"] == "":
      return '{"error": "report id not provided."}'

    with CDbSamples() as db:
      result = db.search_report_by_id(i["id"])
    
    if len(result) == 1:
      return json.dumps(result[0])
    else:
      return json.dumps({"error": "report not found"})

# -----------------------------------------------------------------------
class api_search:
  def GET(self):
    return self.POST()

  def POST(self):
    i = web.input(file_hash="")
    if i["file_hash"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    l = []
    with CDbSamples() as db:
      for q in list(set(i["file_hash"].split(','))):
        ret = db.search_samples(q)
        for row in ret:
          l.append(row)

    if len(l) != 0:
      return json.dumps(l, cls=EnumEncoder)

    return '{"error": "Not found."}'


# -----------------------------------------------------------------------
class api_upload:
  def POST(self):
    i = web.input(file_upload={}, minspeed="-1", allow_internet="false")
    if "file_upload" not in i or i["file_upload"] is None or i["file_upload"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    av_min_speed = AV_SPEED(int(i["minspeed"]))
    av_allow_internet = i["allow_internet"] == "true"

    # Setup the report (the json response)
    report = {
        "hashes": {
          "md5": md5(buf).hexdigest(),
          "sha1": sha1(buf).hexdigest(),
          "sha256": sha256(buf).hexdigest()
        },
        "file": {
          "name": filename,
          "size": len(buf),
        }
    }

    # Persist report to db
    print("webapi: starting insert")
    with CDbSamples() as db:
      report["id"] = db.create_sample_report(filename, buf)
      print("webapi: insert complete") 

      # Queue the file scan
      scan_promise = CAV.scan_buffer(
        buf,
        av_min_speed, 
        av_allow_internet, 
        {"pre": [lambda engine, filename: self.pre_scan_action(report["id"], engine, filename)]})
      
      scan_promise.engine_then(
        lambda res: self.post_engine_scan_action(report["id"], res),
        lambda res: self.post_engine_scan_action(report["id"], res)
      )
      scan_promise.then(
        lambda res: self.post_scan_action(report["id"], res),
        lambda res: self.post_scan_action(report["id"], res)
      )

      print("webapi: scan queued")

      # Create initial scan reports in db
      for engine in scan_promise.get_scanning_engines():
        initial_scan_report = {
          'engine': '',
          'updated': '',
          'name': engine.name,
          'has_internet': engine.container_requires_internet,
          'infected': '',
          'result': '',
          'speed': engine.speed.value,
          'plugin_type': engine.plugin_type.value
        }
        db.add_scan_result(report["id"], initial_scan_report, queued=True, scanning=False)

    return json.dumps(report, cls=EnumEncoder)

  # Function to call after a scan task is processed
  def post_engine_scan_action(self, report_id, res):
    try:
      res = json.loads(res)
      scanner_name = res["name"]

      print("webapi: updateing result from scanner {0}".format(scanner_name))
      with CDbSamples() as db:
        db.update_scan_result(report_id, res, queued=False, scanning=False)
        print("webapi: updated result from {0}".format(scanner_name))
        
        # Update scanner db
        if "error" in res:
          return
        
        signature_version = res["updated"] if "updated" in res else "-"
        engine_version = res["engine"] if "engine" in res else "-"
        plugin_type = res["plugin_type"]
        has_internet = res["has_internet"]
        speed = res["speed"]

        print("webapi: updating scanner data for {0}".format(scanner_name))
        db.update_scanner(scanner_name, plugin_type, has_internet, speed, signature_version, engine_version)
        print("webapi: scanner db update for {0} complete".format(scanner_name))
      
    except Exception as e:
      print("webapi: post engine scan exception")
      print(e)
  
  def post_scan_action(self, report_id, res):
    print("webapi: finishing scan report {0}".format(report_id))
    try:
      with CDbSamples() as db:
        db.finish_sample_report(report_id)
      
      print("webapi: Scan report for {0} finished".format(report_id))
    except Exception as e:
      print("webapi: post scan action exception")
      print(e)
  
  def pre_scan_action(self, report_id, engine, filename):
    print("webapi: scanning file of report {0} with engine {1}...!".format(report_id, engine.name))
    try:
      with CDbSamples() as db:
        db.update_scan_result(report_id, {
          'scanning': True,
          'engine': '',
          'updated': '',
          'name': engine.name,
          'has_internet': engine.container_requires_internet,
          'infected': '',
          'result': '',
          'speed': engine.speed.value,
          'plugin_type': engine.plugin_type.value
        }, queued=False, scanning=True)
      
      print("webapi: state of engine {1} in report {0} is set to scanning".format(report_id, engine.name))
    except Exception as e:
      print("webapi: pre scan action exception")
      print(e)
  
# -----------------------------------------------------------------------
# Legacy non js upload via web form
class upload:
  def POST(self):
    render = web.template.render(TEMPLATE_PATH)

    i = web.input(file_upload={})
    if i["file_upload"] is None or i["file_upload"] == "":
      return render.error("No file uploaded or invalid file.")

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Scan the file
    scan_results = CAV.scan_buffer(buf)

    # Calculate the hashes
    hashes = {
      "md5": md5(buf).hexdigest(),
      "sha1": sha1(buf).hexdigest(),
      "sha256": sha256(buf).hexdigest()
    }

    # File properties
    file_properties = {
      "name": filename,
      "size": len(buf)
    }

    # Persist results to db
    with CDbSamples() as db:
      report_id = db.create_sample_report(filename, buf)

      # Update scanner db
      for scanner_name in scan_results:
        signature_version = scan_results[scanner_name]["updated"] if "updated" in scan_results[scanner_name] else "-"
        engine_version = scan_results[scanner_name]["engine"] if "engine" in scan_results[scanner_name] else "-"
        plugin_type = scan_results[scanner_name]["plugin_type"]
        has_internet = scan_results[scanner_name]["has_inernet"]
        speed = int(scan_results[scanner_name]["speed"])

        db.update_scanner(scanner_name, plugin_type, has_internet, speed, signature_version, engine_version)

    # And show the results
    return render.results(report_id, scan_results, hashes, file_properties)

# -----------------------------------------------------------------------
update_results = {
  "start_date": None,
  "end_date": None,
  "last_refresh": None,
  "results": dict()
}
class update:
  def GET(self):
    # show results
    render = web.template.render(TEMPLATE_PATH, globals={"sorted": sorted, "plugin_type_to_string": plugin_type_to_string})
    update_results['last_refresh'] = datetime.datetime.now()
    return render.update(update_results)

  def _post_engine_update(self, result):
    try:
      print("update of {0} complete!".format(result['engine']))

      # store to temp object
      update_results['results'][result['engine']] = result

      # update db if required
      update_successs = result['status'] != "error"      
      if update_successs:
        plugin_type = result["plugin_type"]
        has_internet = result["has_internet"]
        signature_version = result["signature_version"]
        engine_version = result["signature_version"] if "signature_version" in result else "-"
        speed = int(result["speed"])

        with CDbSamples() as db:
          db.update_scanner(result['engine'], plugin_type, has_internet, speed, signature_version, engine_version)
        
    except Exception as e:
      print("webapi: post engine update exception")
      print(e)

  def _post_update(self, result):
    update_results['end_date'] = datetime.datetime.now()
    print("update process finished")

  def POST(self):
    # Update
    update_results['start_date'] = datetime.datetime.now()
    print("starting update of all containers...")
    update_promise = CAV.update()

    # update temp data structure with results
    update_promise.engine_then(
      lambda res: self._post_engine_update(res),
      lambda res: self._post_engine_update(res)
    ).then(
      lambda res: self._post_update(res),
      lambda res: self._post_update(res)
    )

    # set initial data in temp data structure
    for engine in update_promise.get_scanning_engines():
      update_results["results"][engine.name] = {
          'engine': engine.name,
          'status': "updating...",
          'old_signature_version': "...",
          'old_container_build_time': "...",
          'signature_version': "...",
          'container_build_time': "...",
          'plugin_type': engine.plugin_type,
          'has_internet': engine.container_requires_internet,
          'speed': engine.speed
      }

    return self.GET()

# -----------------------------------------------------------------------
class system:
  def GET(self):
    statistics = scanner_strategy.get_statistics()

    statistics["cpu_count"] = cpu_count()

    render = web.template.render(TEMPLATE_PATH, globals={"type": type})
    return render.system(statistics)