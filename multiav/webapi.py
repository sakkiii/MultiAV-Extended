import os
import sys
import json
import time

import web
from hashlib import md5, sha1, sha256
from itertools import groupby
from multiav.core import CMultiAV, AV_SPEED_ALL, AV_SPEED_ULTRA

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
    '/scanners', 'scanners',
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
                                                sha256 text unique)""")
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
                                                server text,
                                                binary_version text,
                                                engine_data_version text,
                                                active integer,
                                                last_refresh_date text,
                                                last_update_date text)""")
      except:
        print("Error:", sys.exc_info())[1]

  def insert_sample(self, name, buf, reports):
    infected = 0
    for av_name in reports:
      if 'result' in reports[av_name]:
        if reports[av_name]['result'] != {}:
          infected = 1
          break

    md5_hash = md5(buf).hexdigest()
    sha1_hash = sha1(buf).hexdigest()
    sha256_hash = sha256(buf).hexdigest()

    with self.db.transaction():
      try:
        query = "INSERT INTO samples(name, md5, sha1, sha256) SELECT $name, $md5, $sha1, $sha256 WHERE NOT EXISTS(SELECT 1 FROM samples WHERE sha256 = $sha256)"
        insert_ret = self.db.query(query, vars={"name":name, "md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash})
        res = self.search_sample(sha256_hash)
        sample_id = res[0].id

        report_id = self.db.insert('reports', infected=infected, date=time.asctime(), sample_id=sample_id, result=json.dumps(reports) )
        print("Report inserted", sha1_hash)
      except:
        print("Error:", sys.exc_info()[1], md5_hash, sha1_hash, sha256_hash)
    
    # update scanner db
    self._update_scanner_from_report(reports)

  def search_sample(self, file_hash):
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE md5=$hash OR sha1=$hash OR sha256=$hash OR samples.name like $hash"
    print(query)
    rows = self.db.query(query, vars={"hash":file_hash})
    print(rows)
    return rows

  def search_samples(self, value):
    if value is None:
      query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id"
      return self.db.query(query)
    else:
      query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE md5=$val OR sha1=$val OR sha256=$val OR reports.result like $val OR samples.name like $val"
      return self.db.query(query, vars={"val":value})

  def last_samples(self, limit, page):
    offset = limit * page
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id ORDER BY reports.id desc LIMIT $limit OFFSET $offset"
    rows = self.db.query(query, vars={'limit': limit, 'offset': offset})
    return rows

  def get_scanners(self):
    rows = self.db.select("scanners")
    return rows

  def get_scanner(self, name):
    where = 'name like $name'
    rows = self.db.select("scanners", where=where, vals={'name': name})
    return rows

  def insert_scanner(self, scanner):
    row = self.db.insert("scanners",name=scanner['name'], server=scanner['server'], binary_version=scanner['binary_version'], \
                          engine_data_version=scanner['engine_data_version'], active=scanner['active'], \
                          last_refresh_date=time.asctime(), last_update_date=scanner['last_update_date'])
    return row
  
  def _update_scanner_from_report(self, report):
    for scanner in report:
      try:
        updated_rows = self.update_scanner_versions(scanner, 'local',\
            report[scanner]['scanner_binary_version'], report[scanner]['scanner_engine_data_version'])
            
        if updated_rows == 0:
          self.insert_scanner({
            'name': scanner, 
            'server': 'local',
            'binary_version': report[scanner]['scanner_binary_version'],
            'engine_data_version': report[scanner]['scanner_engine_data_version'],
            'active': True,
            'last_update_date': '-'})
      except:
        print("Error:", sys.exc_info())[1]
  
  def update_scanner(self, scanner):
    where='name = $name and server = $server'
    updated_rows = self.db.update("scanners", vars={"name": scanner['name'], "server": scanner['server']}, where=where, \
                          binary_version=scanner['binary_version'], engine_data_version=scanner['engine_data_version'], \
                          active=scanner['active'], last_refresh_date=time.asctime(), last_update_date=scanner['last_update_date'])
    return updated_rows
  
  def update_scanner_versions(self, name, server, binary_version, engine_data_version, last_update_date = None):
    where='name = $name and server = $server'
    if last_update_date == None:
      updated_rows = self.db.update("scanners", vars={"name": name, "server": server}, where=where, \
                          binary_version=binary_version, engine_data_version=engine_data_version, \
                          last_refresh_date=time.asctime(), active=True)
    else:
      updated_rows = self.db.update("scanners", vars={"name": name, "server": server}, where=where, \
                          binary_version=binary_version, engine_data_version=engine_data_version, \
                          last_update_date=last_update_date, last_refresh_date=time.asctime(), active = True)

    return updated_rows

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
      page = int(i['page'])
    else:
      page = 0
    
    rows = db.last_samples(limit, page)
    l = []
    for row in rows:
      l.append([row['name'], json.loads(row['result']), row['md5'], row['sha1'], row['sha256'], row['date']])

    if page == 0:
      backpage = 0
    else:
      backpage = page -1

    render = web.template.render(TEMPLATE_PATH)
    return render.last(l, backpage, page, page + 1)


# -----------------------------------------------------------------------
class search:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    i = web.input(q="")
    if i["q"] == "":
      return render.search()
    
    return self.POST()

  def POST(self):
    render = web.template.render(TEMPLATE_PATH)

    i = web.input(q="")
    if i["q"] == "":
      return render.search()

    db = CDbSamples()
    l = []

    for q in list(set(i["q"].split(','))):
      rows = db.search_samples(q)
      for row in rows:
        l.append([row['name'], json.loads(row['result']), row['md5'], row['sha1'], row['sha256'], row['date']])

    if len(l) == 0:
      return render.error("No match")

    return render.search_results(l, i['q'])


# -----------------------------------------------------------------------
class export_csv:
  def process_query_result(self, rows, headers):
    data = []
    for row in rows:
        data_row = {}
        result = json.loads(row['result'])

        for key, value in result.iteritems():
          version = value['scanner_binary_version'].replace('\n', ' ').replace('\r', '') + \
                    ' ' + \
                    value['scanner_engine_data_version'].replace('\n', ' ').replace('\r', '')
          result = value['result'][value['result'].keys()[0]] if value['result'] != {} else 'clean'

          data_row[key] = result
          data_row[key + '-version'] = version
        
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
    render = web.template.render(TEMPLATE_PATH)
    return render.index()


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
      ret = db_api.search_sample(q)
      for row in ret:
        l.append(row)

    if len(l) != 0:
      return json.dumps(l)

    return '{"error": "Not found."}'


# -----------------------------------------------------------------------
class api_upload:
  def POST(self):
    i = web.input(file_upload={})
    if "file_upload" not in i or i["file_upload"] is None or i["file_upload"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Calculate the hashes
    report = {
        "hashes": {
            "md5": md5(buf).hexdigest(),
            "sha1": sha1(buf).hexdigest(),
            "sha256": sha256(buf).hexdigest()
        }
    }

    # Scan the file
    av = CMultiAV()
    scan_result = av.scan_buffer(buf)
    report.update(scan_result)

    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, scan_result)
    return json.dumps(report)


# -----------------------------------------------------------------------
class api_upload_fast:
  def POST(self):
    i = web.input(file_upload={}, speed=AV_SPEED_ULTRA)
    if i["file_upload"] is None or i["file_upload"] == "":
      return "{'error':'No file uploaded or invalid file.'}"

    speed = int(i["speed"])
    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Calculate the hashes
    report = {
        "hashes": {
            "md5": md5(buf).hexdigest(),
            "sha1": sha1(buf).hexdigest(),
            "sha256": sha256(buf).hexdigest()
        }
    }

    # Scan the file
    av = CMultiAV()
    scan_result = av.scan_buffer(buf, speed)
    report.update(scan_result)

    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, scan_result)

    return json.dumps(report)


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
    ret = av.scan_buffer(buf)

    # Calculate the hashes
    hashes = []
    hashes.append(md5(buf).hexdigest())
    hashes.append(sha1(buf).hexdigest())
    hashes.append(sha256(buf).hexdigest())

    # Save the sample
    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, ret)

    # And show the results
    return render.results(ret, filename, hashes)

# -----------------------------------------------------------------------
class scanners:
  def GET(self):
    # Get the scanners from db
    db_api = CDbSamples()
    rows = db_api.get_scanners()

    # Groupby server
    scanservers = {}
    for server, scanners in groupby(rows, lambda x: x['server']):
      if not server in scanservers:
        scanservers[server] = []

      for scanner in scanners:
        scanservers[server].append(scanner) 

    # And show the results
    render = web.template.render(TEMPLATE_PATH)
    return render.scanners(scanservers)

  def POST(self):
    # Get the scanners from db
    db_api = CDbSamples()
    db_scanners = db_api.get_scanners().list()

    # Get current versions from API
    av = CMultiAV()
    binary_versions = av.get_binary_versions()['local']
    engine_data_versions = av.get_engine_data_versions()['local']

    # Set inactive ones
    for scanner in db_scanners:
      if not scanner['name'] in binary_versions:
        scanner['active'] = False
        db_api.update_scanner(scanner)
 
    # Update active ones
    for scanner in binary_versions:
      try:
        rows_updated = db_api.update_scanner_versions(scanner, 'local',  binary_versions[scanner], engine_data_versions[scanner])
        if rows_updated == 0:
          db_api.insert_scanner({
            'name': scanner, 
            'server': 'local',
            'binary_version': binary_versions[scanner],
            'engine_data_version': engine_data_versions[scanner],
            'active': True,
            'last_update_date': '-'}
)
      except:
        print("Error:", sys.exc_info())[1]

    return self.GET()

# -----------------------------------------------------------------------
class update:
  def POST(self):
    # Update
    av = CMultiAV()
    update_results = av.update()
    binary_versions = av.get_binary_versions()['local']
    engine_data_versions = av.get_engine_data_versions()['local']

    # Set old / new versions in result
    db_api = CDbSamples()
    db_scanners = db_api.get_scanners().list()

    for server, scanners in groupby(db_scanners, lambda x: x['server']):
      for scanner in scanners:
        update_successs = update_results[server][scanner.name]['status']

        update_results[server][scanner.name]['old_binary_version'] = scanner.binary_version
        update_results[server][scanner.name]['old_engine_data_version'] = scanner.engine_data_version

        update_results[server][scanner.name]['new_binary_version'] = binary_versions[scanner.name] if update_successs else '-'
        update_results[server][scanner.name]['new_engine_data_version'] = engine_data_versions[scanner.name] if update_successs else '-'
        
        # Update DB with new versions
        if update_successs:
          db_api.update_scanner_versions(scanner, 'local', binary_versions[scanner.name], engine_data_versions[scanner.name], time.asctime())

    # Show the results
    render = web.template.render(TEMPLATE_PATH)
    return render.update(update_results)