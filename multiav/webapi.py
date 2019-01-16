import os
import sys
import json
import time

import web
from hashlib import md5, sha1, sha256
from itertools import groupby
from multiav.core import CMultiAV, AV_SPEED_ALL

urls = (
    '/', 'index',
    '/upload', 'upload',
    '/api/upload', 'api_upload',
    '/api/upload_fast', 'api_upload_fast',
    '/api/search', 'api_search',
    '/about', 'about',
    '/last', 'last',
    '/search', 'search',
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
        print "Error:", sys.exc_info()[1]

  def insert_sample(self, name, buf, reports):
    infected = 0
    for av_name in reports:
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
        print "Report inserted", sha1_hash
      except:
        print "Error:", sys.exc_info()[1], md5_hash, sha1_hash, sha256_hash

  def search_sample(self, file_hash):
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE md5=$hash OR sha1=$hash OR sha256=$hash"
    print(query)
    rows = self.db.query(query, vars={"hash":file_hash})
    print(rows)
    return rows

  def search_samples(self, value):
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE md5=$val OR sha1=$val OR sha256=$val OR reports.result like $val OR samples.name like $val"
    rows = self.db.query(query, vars={"val":value})
    return rows

  def last_samples(self):
    query = "SELECT samples.id,samples.name,samples.md5,samples.sha1,samples.sha256,reports.id AS report_id,reports.infected,reports.date,reports.result FROM samples LEFT JOIN reports ON samples.id = reports.sample_id WHERE reports.infected = 1 ORDER BY reports.date desc LIMIT 20"
    rows = self.db.query(query)
    return rows

  def get_scanners(self):
    rows = self.db.select("scanners")
    return rows

  def insert_scanner(self, scanner):
    row = self.db.insert("scanners",name=scanner['name'], server=scanner['server'], binary_version=scanner['binary_version'], \
                          engine_data_version=scanner['engine_data_version'], active=scanner['active'], \
                          last_refresh_date=time.asctime(), last_update_date=scanner['last_update_date'])
    return row
  
  def update_scanner(self, scanner):
    where='name = $name and server = $server'
    row = self.db.update("scanners", vars={"name": scanner['name'], "server": scanner['server']}, where=where, \
                          binary_version=scanner['binary_version'], engine_data_version=scanner['engine_data_version'], \
                          active=scanner['active'], last_refresh_date=time.asctime(), last_update_date=scanner['last_update_date'])
    return row

# -----------------------------------------------------------------------
class last:
  def GET(self):
    db = CDbSamples()
    rows = db.last_samples()
    l = []
    for row in rows:
      l.append([row['name'], json.loads(row['result']), row['md5'], row['sha1'], row['sha256'], row['date']])

    render = web.template.render(TEMPLATE_PATH)
    return render.search_results(l)


# -----------------------------------------------------------------------
class search:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    return render.search()

  def POST(self):
    render = web.template.render(TEMPLATE_PATH)
    i = web.input(q="")
    if i["q"] == "":
      return render.search()

    db = CDbSamples()
    rows = db.search_samples(i["q"])
    l = []
    for row in rows:
      l.append([row['name'], json.loads(row['result']), row['md5'], row['sha1'], row['sha256'], row['date']])

    if len(l) == 0:
      return render.error("No match")
    return render.search_results(l)


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
    ret = db_api.search_sample(i["file_hash"])
    for row in ret:
      return json.dumps(row)
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
    report.update(av.scan_buffer(buf))

    db_api.insert_sample(filename, buf, report)
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
    report.update(av.scan_buffer(buf, speed))

    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, report)

    return json.dumps(report)


# -----------------------------------------------------------------------
class upload:
  def POST(self):
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
    render = web.template.render(TEMPLATE_PATH)
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
      scanner_last_update_db = filter(lambda x: x.name == scanner, db_scanners)
      updated_scanner = {
        'name': scanner, 
        'server': 'local',
        'binary_version': binary_versions[scanner],
        'engine_data_version': engine_data_versions[scanner],
        'active': True,
        'last_update_date': scanner_last_update_db[0].last_update_date if len(scanner_last_update_db) == 1 else '-'}

      try:
        if len(scanner_last_update_db) == 1:
          db_api.update_scanner(updated_scanner)
        else:
          db_api.insert_scanner(updated_scanner)
      except:
        print "Error:", sys.exc_info()[1]

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
        update_results[server][scanner.name]['old_binary_version'] = scanner.binary_version
        update_results[server][scanner.name]['old_engine_data_version'] = scanner.engine_data_version
        update_results[server][scanner.name]['new_binary_version'] = binary_versions[scanner.name]
        update_results[server][scanner.name]['new_engine_data_version'] = engine_data_versions[scanner.name]

    # Update DB with new versions
    for server in update_results:
      for scanner in update_results[server]:
        if update_results[server][scanner]['status']:
          db_scanner = filter(lambda x: x.name == scanner, db_scanners)

          #persist last update time & version
          updated_scanner = {
            'name': scanner, 
            'server': 'local',
            'binary_version': binary_versions[scanner],
            'engine_data_version': engine_data_versions[scanner],
            'active': True,
            'last_refresh_date': db_scanner[0].last_refresh_date if len(db_scanner) == 1 else '-',
            'last_update_date': time.asctime()}
          db_api.update_scanner(updated_scanner)

    # Show the results
    render = web.template.render(TEMPLATE_PATH)
    return render.update(update_results)