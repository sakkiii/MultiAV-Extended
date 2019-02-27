import os
import sys
import json
import time

import web
from hashlib import md5, sha1, sha256
from itertools import groupby
from multiprocessing import cpu_count
from multiav.core import CMultiAV, AV_SPEED, PLUGIN_TYPE, EnumEncoder

urls = (
    '/', 'index',
    '/upload', 'upload',
    '/api/upload', 'api_upload',
    '/api/upload_fast', 'api_upload_fast',
    '/api/search', 'api_search',
    '/about', 'about',
    '/last', 'last',
    '/search', 'search',
    '/export/csv', 'export_csv',
    '/update', 'update'
)

app = web.application(urls, globals())
ROOT_PATH = os.path.dirname(__file__)
CURRENT_PATH = os.getcwd()
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

if not os.path.isdir(os.path.join(CURRENT_PATH, 'static')):
    raise Exception('runserver.py must be run in the directory {0}'.format(ROOT_PATH))

# -----------------------------------------------------------------------
class CDbSamples:
  def __init__(self):
    self.db = web.database(dbn='sqlite', db='multiav.db')
    self.db.printing = False
    self.create_schema()

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
                                                date text,
                                                result text,
                                                FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE)""")
        self.db.query("""create table if not exists scanners(
                                                id integer not null primary key autoincrement,
                                                name text,
                                                plugin_type integer,
                                                signature_version text,
                                                engine_version text,
                                                has_internet integer,
                                                speed text)""")
      except:
        print("Error:", sys.exc_info())[1]

  def insert_sample_report(self, name, buf, reports):
    # calculate infected percentage
    result_clean = 0
    for av_name in reports:
      if 'result' in reports[av_name]:
        if reports[av_name]['result'] != {}:
          result_clean += 1

    if result_clean == 0:
      infected = 0
    else:
      infected = ( result_clean / len(reports) ) * 100

    # calculate file properties
    md5_hash = md5(buf).hexdigest()
    sha1_hash = sha1(buf).hexdigest()
    sha256_hash = sha256(buf).hexdigest()
    size = len(buf)

    with self.db.transaction():
      try:
        # insert sample if not exists
        query = "INSERT INTO samples(name, md5, sha1, sha256, size) SELECT $name, $md5, $sha1, $sha256, $size WHERE NOT EXISTS(SELECT 1 FROM samples WHERE sha256 = $sha256)"
        self.db.query(query, vars={"name":name, "md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash, "size": size})
        
        # get sample id
        res = self.search_sample_by_hash(sha256_hash)
        sample_id = res[0].id

        # insert report with sample_id
        report_id = self.db.insert('reports', infected=infected, date=time.asctime(), sample_id=sample_id, result=json.dumps(reports, cls=EnumEncoder) )

        return report_id
      except:
        print("Error:", sys.exc_info()[1], md5_hash, sha1_hash, sha256_hash)
        return -1

  def search_report_by_id(self, report_id):
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE report_id = $report_id"
    rows = self.db.query(query, vars={"report_id": report_id})
    return rows

  def search_sample_by_hash(self, file_hash):
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE md5=$hash OR sha1=$hash OR sha256=$hash OR samples.name like $hash"
    rows = self.db.query(query, vars={"hash":file_hash})
    return rows

  def search_samples(self, value):
    if value is None:
      query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id"
      return self.db.query(query)
    else:
      query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE md5=$val OR sha1=$val OR sha256=$val OR reports.result like $val OR samples.name like $val"
      return self.db.query(query, vars={"val":value})

  def count_reports(self):
      query = "SELECT COUNT(*) FROM reports"
      return int(list(self.db.query(query))[0]["COUNT(*)"])

  def last_samples(self, limit, page):
    offset = limit * page
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,samples.size,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id ORDER BY reports.id desc LIMIT $limit OFFSET $offset"
    rows = self.db.query(query, vars={'limit': limit, 'offset': offset})
    return rows

  def get_scanners(self):
    rows = self.db.select("scanners")
    return rows

  def get_scanner(self, name):
    where = 'name like $name'
    rows = self.db.select("scanners", where=where, vals={'name': name})
    return rows

  def insert_scanner(self, name, plugin_type, has_internet, signature_version, engine_version, speed):
    if type(plugin_type) is PLUGIN_TYPE:
      plugin_type_value = plugin_type.value
    else:
      plugin_type_value = plugin_type

    has_internet = 1 if has_internet == True else 0
      
    row = self.db.insert("scanners",name=name, plugin_type=plugin_type_value, has_internet=has_internet, speed=speed, \
                          signature_version=str(signature_version), engine_version=str(engine_version))
    return row
    
  def update_scanner(self, name, plugin_type, has_internet, signature_version, engine_version = None, speed=None):
    if type(plugin_type) is PLUGIN_TYPE:
      plugin_type_value = plugin_type.value
    else:
      plugin_type_value = plugin_type
    
    where='name = $name'
    has_internet = 1 if has_internet == True else 0
    
    if engine_version is not None:
      updated_rows = self.db.update("scanners", vars={"name": name}, where=where, \
                          plugin_type=plugin_type_value, has_internet=has_internet, \
                          signature_version=str(signature_version), engine_version=str(engine_version))
    else:
      updated_rows = self.db.update("scanners", vars={"name": name}, where=where, \
                          plugin_type=plugin_type_value, has_internet=has_internet, \
                          signature_version=str(signature_version))
    
    # insert new scanner if none existed)
    if updated_rows == 0:
      self.insert_scanner(name, plugin_type, has_internet, signature_version, \
         engine_version if engine_version is not None else "-", speed if speed is not None else "-")

    return updated_rows

# -----------------------------------------------------------------------
def convert_result_rows_to_ui_datastructure(rows):
  result_array = []
  for scan_result in rows:
        # calculate additionally used data and setup result object
        result = {
          "date": scan_result['date'],
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
        result_data = json.loads(scan_result['result'])
        for plugin_name in result_data.keys():
          # store result
          plugin_type = PLUGIN_TYPE(result_data[plugin_name]["plugin_type"])
          result[plugin_type][plugin_name] = result_data[plugin_name]

          if plugin_type == PLUGIN_TYPE.AV or plugin_type == PLUGIN_TYPE.LEGACY:
            # update statistics
            has_error, error = result_has_error(result_data[plugin_name])
            if not has_error:
              result["statistics"]["engine_count"] += 1

              if result_data[plugin_name]["infected"]:
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
  if not "error" in result.keys():
    return (False, None)
  
  if result["error"] == "":
    return (False, None)
  
  return (True, result["error"])

# -----------------------------------------------------------------------
class last:
  def GET(self):
    db = CDbSamples()
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
    db = CDbSamples()
    querylist = []
    search = None

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
          if value["plugin_type"] == PLUGIN_TYPE.LEGACY or value["plugin_type"] == PLUGIN_TYPE.AV:
            version = value['engine'].replace('\n', ' ').replace('\r', '') + \
                      ' ' + \
                      value['updated'].replace('\n', ' ').replace('\r', '')

            has_error, error = result_has_error(value)

            if has_error:
              result = error
            else:
              # e.g. fsecure' returning results of 2 engines
              if "results" in value.keys():
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
    db = CDbSamples()
    headers = ['name', 'md5', 'sha1', 'sha256', 'date']
    data = []

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
      engines.update(row.keys())
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
    db_api = CDbSamples()
    db_scanners = db_api.get_scanners().list()

    render = web.template.render(TEMPLATE_PATH, globals={"sorted": sorted, "plugin_type_to_string": plugin_type_to_string})
    return render.index(db_scanners, cpu_count())


# -----------------------------------------------------------------------
class about:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    return render.about()


# -----------------------------------------------------------------------
class api_search:
  def GET(self):
    return self.POST()

  def POST(self):
    i = web.input(file_hash="")
    if i["file_hash"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    db_api = CDbSamples()
    l = []
    for q in list(set(i["file_hash"].split(','))):
      ret = db_api.search_samples(q)
      for row in ret:
        l.append(row)

    if len(l) != 0:
      return json.dumps(l, cls=EnumEncoder)

    return '{"error": "Not found."}'


# -----------------------------------------------------------------------
class api_upload:
  def POST(self):
    i = web.input(file_upload={}, minspeed="all", allow_internet="false")
    if "file_upload" not in i or i["file_upload"] is None or i["file_upload"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    av_min_speed = AV_SPEED(int(i["minspeed"]))
    av_allow_internet = i["allow_internet"] == "true"

    # Setup the report
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

    # Scan the file
    av = CMultiAV()
    scan_results = av.scan_buffer(buf, av_min_speed, av_allow_internet)
    print("webapi: scan complete")
    report.update(scan_results)
    print("webapi: update report dict complete")

    # Persist result to db
    db_api = CDbSamples()
    print("webapi: starting insert")
    report["id"] = db_api.insert_sample_report(filename, buf, scan_results)
    print("webapi: insert complete")

    # Update scanner db
    print("webapi: starting scanner db update")
    for scanner_name in scan_results:
      if "error" in scan_results[scanner_name]:
        continue
      
      signature_version = scan_results[scanner_name]["updated"] if "updated" in scan_results[scanner_name] else "-"
      engine_version = scan_results[scanner_name]["engine"] if "engine" in scan_results[scanner_name] else "-"
      plugin_type = scan_results[scanner_name]["plugin_type"]
      has_internet = scan_results[scanner_name]["has_internet"]
      speed = scan_results[scanner_name]["speed"]

      db_api.update_scanner(scanner_name, plugin_type, has_internet, signature_version, engine_version, speed)

    print("webapi: scanner db update complete")
    return json.dumps(report, cls=EnumEncoder)

# -----------------------------------------------------------------------
class upload:
  def POST(self):
    render = web.template.render(TEMPLATE_PATH)

    i = web.input(file_upload={})
    if i["file_upload"] is None or i["file_upload"] == "":
      return render.error("No file uploaded or invalid file.")

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Scan the file
    av = CMultiAV()
    scan_results = av.scan_buffer(buf)

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
    db_api = CDbSamples()
    report_id = db_api.insert_sample_report(filename, buf, scan_results)

    # Update scanner db
    for scanner_name in scan_results:
      signature_version = scan_results[scanner_name]["updated"] if "updated" in scan_results[scanner_name] else "-"
      engine_version = scan_results[scanner_name]["engine"] if "engine" in scan_results[scanner_name] else "-"
      plugin_type = scan_results[scanner_name]["plugin_type"]
      has_internet = scan_results[scanner_name]["has_inernet"]
      speed = scan_results[scanner_name]["speed"]

      db_api.update_scanner(scanner_name, plugin_type, has_internet, signature_version, engine_version, speed)

    # And show the results
    return render.results(report_id, scan_results, hashes, file_properties)

# -----------------------------------------------------------------------
class update:
  def POST(self):
    # Update
    av = CMultiAV()
    update_results = av.update()

    # Update DB with new versions    
    db_api = CDbSamples()
    for scanner in update_results:
      update_successs = update_results[scanner]['status'] != "error"
      
      if update_successs:
        plugin_type = update_results[scanner]["plugin_type"]
        has_internet = update_results[scanner]["has_inernet"]
        signature_version = update_results[scanner]["signature_version"]
        speed = update_results[scanner]["speed"]

        db_api.update_scanner(scanner, plugin_type, has_internet, signature_version, speed)

    # Show the results
    render = web.template.render(TEMPLATE_PATH, globals={"sorted": sorted, "plugin_type_to_string": plugin_type_to_string})
    return render.update(update_results)