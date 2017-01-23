import time
import BaseHTTPServer
import urlparse
import datetime
import urllib
import re
import subprocess
import os
import json
import base64
import urllib2
from threading import *


HOST_NAME = 'localhost'
PORT_NUMBER = 9000
PATTERN_FOR_ENC_KEY = re.compile(r'URI="(.*?)"')
PATTERN_FOR_SERV = re.compile(r'nlds(.*?)\.cdnak')
SERV = "serv"
QUARTER = "q"
TEAMG = "teamg"
TEAMH = "teamh"

lock_for_key = RLock()
keys_cache = dict()
games_table = []


class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse.urlparse(self.path).path
        query = urlparse.urlparse(self.path).query
        query_components = urlparse.parse_qs(query)
        # query_components = dict(qc.split("=") for qc in query.split("&"))
        print "path string: ", path
        print "queries: ", query_components
        if path.endswith(".m3u8"):
            print "m3u8 mode"
            if not (query_components.has_key(TEAMH) and query_components.has_key(
                    TEAMG) and query_components.has_key(QUARTER) and query_components.has_key(SERV)):
                self.show_error("some params are missing")
                return
            self.write_as_m3u8(query_components.get(TEAMH)[0], query_components.get(TEAMG)[0],
                               query_components.get(QUARTER)[0],
                               query_components.get(SERV)[0])
        elif path.endswith(".xml"):
            print "xml mode"
            self.show_crossdomain()
        elif path.endswith(".html"):
            print "html mode"
            self.list_games()
        elif path.endswith(".key"):
            print "key mode"
            if not (query_components.has_key(TEAMH) and query_components.has_key(
                    TEAMG) and query_components.has_key(QUARTER) and query_components.has_key(SERV)):
                self.show_error("some params are missing")
                return
            self.show_key(query_components.get(TEAMH)[0], query_components.get(TEAMG)[0],
                          query_components.get(QUARTER)[0],
                          query_components.get(SERV)[0])
        else:
            self.show_error("invalid page")

    def show_error(self, error):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(error)

    def list_games(self):
        global games_table
        list_of_games = games_table[:]
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        for game in list_of_games:
            self.wfile.write(game + "<br>")

    def show_key(self, teamh, teamg, q, serv):
        global keys_cache
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.end_headers()
        curr_stamp = time.time() - 3600 * 3
        date_part = datetime.datetime.fromtimestamp(
            int(curr_stamp)
        ).strftime('%Y%m%d')
        print date_part
        cache_key = date_part + teamh + teamg + q
        res = ""

        lock_for_key.acquire()
        try:
            if cache_key not in keys_cache or (curr_stamp - keys_cache.get(cache_key)[0]) > 150:
                print "not in cache"
                url = "http://nlds" + serv + ".cdnak.neulion.com/nlds/nba/" + teamh + "/as/live/" + teamh + "_hd_" + str(
                    q) + "_ipad.m3u8"
                print url

                f_m3u8 = urllib.urlopen(url)
                content_m3u8 = f_m3u8.read()
                key_url_re = re.search(PATTERN_FOR_ENC_KEY, content_m3u8)
                key_url = key_url_re.groups()[0]
                print "key_url: " + key_url
                key_url_64 = base64.b64encode(key_url)
                url_req_part = "l=nba&g=" + teamg.upper() + "-" + teamh.upper() + "-" + date_part + "&f=HOME&u=" + key_url_64
                full_url = "http://www.hdsports.ca/live/k2.php?q=" + base64.b64encode(url_req_part)
                print full_url
                file_key = urllib.urlopen(full_url).read()
                keys_cache[cache_key] = (curr_stamp, file_key)
                f = open(cache_key + serv + ".key", 'w+')
                f.write(file_key)
                f.close()
            else:
                print "in cache"
            res = keys_cache.get(cache_key)[1]
        finally:
            lock_for_key.release()
        self.wfile.write(res)

    def show_crossdomain(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        self.wfile.write(
            """
            <?xml version="1.0"?>
            <!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
                <cross-domain-policy>
                    <allow-access-from domain="*" />
                </cross-domain-policy>
            """
        )

    def write_as_m3u8(self, teamh, teamg, q, serv):
        self.send_response(200)
        self.send_header("Content-type", "application/vnd.apple.mpegurl")
        self.end_headers()
        os.environ['TZ'] = 'GMT'
        # time.tzset()
        offset = -40
        now = datetime.datetime.utcnow()
        ptime = str(int(time.time() - 3600 * 3))[:-1] + "0"
        print ptime
        start_time = 1368059400
        quality = q
        self.wfile.write("#EXTM3U\n")
        self.wfile.write("#EXT-X-TARGETDURATION:10\n")
        self.wfile.write(
            "#EXT-X-KEY:METHOD=AES-128,URI=\"http://" + HOST_NAME + ":" + str(PORT_NUMBER) + "/test.key?teamh="
            + teamh + "&teamg=" + teamg + "&serv=" + serv + "&q=" + q + "\"\n")
        self.wfile.write("#EXT-X-MEDIA-SEQUENCE:" + str((int(ptime) - start_time) / 10) + "\n")
        i = 0
        while (i >= -20):
            self.wfile.write("#EXTINF:10,\n")
            self.wfile.write(
                "http://nlds" + serv + ".cdnak.neulion.com/nlds/nba/" + teamh + "/as/live/" + teamh + "_hd_" + str(
                    quality) + "_" + datetime.datetime.fromtimestamp(int(ptime) + (offset - i) * 10).strftime(
                    "%Y%m%d%H%M%S") + ".ts\n")
            i -= 1


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        # init in this thread
        self.function(*self.args, **self.kwargs)
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


def test_parse(gameid):
    content, response_code = fetch_thing(
        'http://www.hdsports.ca/live/get_feeds_v2.php',
        {'game_id': gameid, 'league': "nba"},
        'POST'
    )
    return content


def fetch_thing(url, params, method):
    params = urllib.urlencode(params)
    if method == 'POST':
        f = urllib.urlopen(url, params)
    else:
        f = urllib.urlopen(url + '?' + params)
    return (f.read(), f.code)


def update_table():
    global games_table
    # games_table=[]
    games_table_local = []
    content, response_code = fetch_thing('http://www.hdsports.ca/live/scores/', {'q': "nba"}, 'GET')
    json_games = json.loads(content)
    if not json_games['status'] == "success":
        return
    for game in json_games['results']:
        if game[2] == 'In Progress':
            m3u8_code_json = json.loads(test_parse(game[0]))
            if not m3u8_code_json['status'] == "success":
                continue
            serv_url = m3u8_code_json['feeds']['HOME']
            serv_url_re = re.search(PATTERN_FOR_SERV, serv_url)
            serv = serv_url_re.groups()[0]
            teams = game[0].split('-')
            local_url = 'http://' + HOST_NAME + ':' + str(PORT_NUMBER) + '/test.m3u8?teamh=' + teams[1].lower() + '&teamg=' + \
                        teams[0].lower() + '&serv=' + serv + '&q=3000'
            print local_url
            games_table_local.append(local_url)

    if games_table_local:
        games_table = games_table_local


if __name__ == '__main__':
    print "starting timer..."
    rt = RepeatedTimer(60 * 15, update_table)
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    # subprocess.Popen(['/Applications/VLC.app/Contents/MacOS/VLC','http://localhost:9000','--http-continuous','--quiet'])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)