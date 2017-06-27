import traceback
import argparse
import time

__author__ = 'cb'
__version__ = "2.0-6"

import sqlite3
from isight_api import ISightAPI
import os
import sys
import logging
from contextlib import contextmanager
import json
import ipaddr
import csv
from cStringIO import StringIO
from collections import defaultdict

from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo
import cbapi

from util import create_stdout_log, create_rotating_log

import ConfigParser
from tempfile import NamedTemporaryFile

_logger = None
CB_ISIGHT_ROOT = '/var/run/cb/isight-connector'


class FatalError(Exception):
    pass


def connect_local_cbapi(local_server_url, api_token):
    return cbapi.CbApi(local_server_url, token=api_token, ssl_verify=False,
                       ignore_system_proxy=True)


class Bridge(object):
    RISK_RATING_MAP = {
        'LOW': 50,
        'MEDIUM': 60,
        'HIGH': 70,
        'CRITICAL': 100
    }

    DEFAULT_RISK = 'MEDIUM'
    UNKNOWN_RISK = 100
    INTERESTED_CHARACTERIZATIONS = ['Attacker', 'Compromised']

    def __init__(self, api_route, api_key, sec_key, temp_file_location='/tmp'):
        self.isight_api = ISightAPI(api_route, api_key, sec_key)
        self.cache_db_name = os.path.join(temp_file_location, 'isight_cache.db')
        self.cache_db = sqlite3.connect(self.cache_db_name)
        self.set_up_cache()

    def set_up_cache(self):
        self.cache_db.execute('''CREATE TABLE IF NOT EXISTS isight_cache
        (report_id TEXT, report_publish_date INT, report_json_content TEXT)''')

    def perform(self, history_in_days=30):
        _logger.info("Contacting iSIGHT for IOCs for last {0:d} days".format(history_in_days))
        reports = json.loads(self.isight_api.get_iocs(history_in_days, format='json'))
        report_set = set()
        for report in reports['message']:
            report_set.add((report['reportLink'].split('/')[-1], long(report['publishDate'])))

        reports = self.process_reports(report_set)
        return reports

    def perform_iocs(self, history_in_days=30, iocs_only=True):
        _logger.info("Contacting iSIGHT for IOCs for last {0:d} days".format(history_in_days))
        reports = {}

        if iocs_only:
            iocs = StringIO(self.isight_api.get_iocs(history_in_days, format='csv'))
        else:
            iocs = StringIO(self.isight_api.get_i_and_w(history_in_days, format='csv'))

        for row in csv.DictReader(iocs):
            report_id = row['reportId']

            try:
                timestamp = int(row['publishDate'])
            except ValueError as e:
                _logger.error("Invalid publishDate for reportId %s: %s. Setting to today's date." % (report_id,
                                                                                                     row[
                                                                                                         'publishDate']))
                timestamp = int(time.time())

            if report_id not in reports.keys():
                # add new report metadata
                reports[report_id] = {
                    'id': report_id,
                    'title': row['title'],
                    'link': row['webLink'],
                    'timestamp': timestamp,
                    'iocs': defaultdict(set)
                }

            report = reports[report_id]

            if row['cidr']:
                cidr_block = unicode(row['cidr'])
                cidr_block = ipaddr.IPv4Network(cidr_block)
                if cidr_block.numhosts <= 256:
                    report['iocs']['ipv4'].update([unicode(x) for x in cidr_block.iterhosts()])
                else:
                    _logger.info("Ignoring larger than /24 netblock ({0:s})".format(cidr_block))
            if row['ip']:
                report['iocs']['ipv4'].add(unicode(row['ip']))
            if row['domain']:
                report['iocs']['dns'].add(row['domain'])
            if row['md5']:
                report['iocs']['md5'].add(row['md5'])

        reports_with_iocs = [v for k, v in reports.iteritems() if len(v['iocs'])]
        for report in reports_with_iocs:
            for ioc_type in report['iocs']:
                report['iocs'][ioc_type] = list(report['iocs'][ioc_type])

        return reports_with_iocs

    def process_reports(self, report_set):
        reports = []

        # filter for reports that actually have content
        for report_id in report_set:
            raw_report = self.get_report(report_id)
            if not raw_report:
                continue
            if 'message' not in raw_report:
                continue
            raw_report = raw_report['message']
            if 'report' not in raw_report:
                continue
            raw_report = raw_report['report']

            report = dict(raw_report=raw_report, iocs={}, id=report_id[0], timestamp=report_id[1])
            reports.append(report)

        # get indicators and score for each report
        for report_entry in reports:
            report = report_entry['raw_report']

            report_entry['title'] = report.get('title', '')
            report_entry['link'] = "https://mysight.isightpartners.com/report/full/{0:s}".format(report_entry['id'])

            risk_rating = report.get('riskRating', Bridge.DEFAULT_RISK)
            report_entry['score'] = Bridge.RISK_RATING_MAP.get(risk_rating, Bridge.UNKNOWN_RISK)

            if 'tagSection' in report:
                if 'networks' in report['tagSection']:
                    _logger.debug("adding network section to {0:s}".format(report_entry['id']))
                    report_entry['iocs'].update(
                        self.parse_network_iocs(
                            [ioc for ioc in report['tagSection']['networks']['network']
                             if ioc.get('identifier', None) in Bridge.INTERESTED_CHARACTERIZATIONS]))
                if 'files' in report['tagSection']:
                    _logger.debug("adding file section to {0:s}".format(report_entry['id']))
                    report_entry['iocs'].update(
                        self.parse_file_iocs(
                            [ioc for ioc in report['tagSection']['files']['file']
                             if ioc.get('identifier', None) in Bridge.INTERESTED_CHARACTERIZATIONS]))

        return [r for r in reports if len(r['iocs'])]

    def parse_network_iocs(self, report_iocs):
        ipaddrs = set()
        domains = set()
        for ioc in report_iocs:
            if 'cidr' in ioc:
                # expand out ip addresses if we are <= /24
                cidr_block = unicode(ioc['cidr'])
                cidr_block = ipaddr.IPv4Network(cidr_block)
                if cidr_block.numhosts <= 256:
                    ipaddrs.update([unicode(x) for x in cidr_block.iterhosts()])
                else:
                    _logger.info("Ignoring larger than /24 netblock ({0:s})".format(cidr_block))
            if 'ip' in ioc:
                ipaddrs.add(unicode(ioc['ip']))
            if 'domain' in ioc:
                domains.add(ioc['domain'])

        ret = {}
        if len(ipaddrs):
            ret['ipv4'] = list(ipaddrs)
        if len(domains):
            ret['dns'] = list(domains)

        return ret

    def parse_file_iocs(self, report_iocs):
        md5s = set()
        for ioc in report_iocs:
            if 'md5' in ioc:
                md5s.add(ioc['md5'])

        ret = {}
        if len(md5s):
            ret['md5'] = list(md5s)

        return ret

    # TODO: add error checking
    def get_report(self, report_key):
        cur = self.cache_db.cursor()
        req = cur.execute("SELECT report_json_content FROM isight_cache WHERE report_id=? AND report_publish_date=?",
                          report_key)
        content = req.fetchone()
        if content:
            _logger.debug("Found cached report for {0:s} published on {1:d}".format(report_key[0], report_key[1]))
            content = json.loads(content[0])
        else:
            try:
                content = self.isight_api.get_report(report_key[0], format='json')
            except:
                _logger.debug("Exception retrieving report {0:s}: ".format(report_key[0]) + traceback.format_exc())
                return None

            _logger.debug(
                "Inserting report {0:s} published on {1:d} into local cache".format(report_key[0], report_key[1]))
            cur.execute('''INSERT INTO isight_cache(report_id, report_publish_date, report_json_content)
            VALUES (?, ?, ?)''', (report_key[0], report_key[1], content))
            self.cache_db.commit()
            content = json.loads(content)

        return content


@contextmanager
def file_lock(lock_file):
    if os.path.exists(lock_file):
        pid = file(lock_file).read()
        print 'Only one instance can run at once. ' \
              'Script is locked with %s (pid: %s)' % (lock_file, pid)
        sys.exit(-1)
    else:
        open(lock_file, 'w').write("%d" % os.getpid())
        try:
            yield
        finally:
            os.remove(lock_file)


def print_reports(reports):
    for report in reports:
        print 'report {0:s} (id {1:s} link {2:s}):'.format(report['title'], report['id'], report['link'])
        for indicator_type in report['iocs']:
            for indicator_value in report['iocs'][indicator_type]:
                print indicator_type, indicator_value


def runner(configpath, export_mode, loglevel=logging.DEBUG):
    with file_lock(os.path.join(CB_ISIGHT_ROOT, 'isight.pid')):
        logfilename = "/var/log/cb/integrations/isight/isight.log"
        global _logger
        if export_mode:
            _logger = create_stdout_log("cb-isight", loglevel)
        else:
            _logger = create_rotating_log("cb-isight", logfilename, loglevel, 1048576, 10)

        try:
            if not export_mode:
                print "Cb-iSIGHT {0:s} Running (could take a while). Check status: {1:s}".format(__version__,
                                                                                                 logfilename)
            return perform(configpath, export_mode)
        except:
            _logger.error("%s" % traceback.format_exc())
            return -1


def perform(configpath, export_mode):
    if not os.path.exists(configpath):
        raise FatalError("Config File %s does not exist!" % configpath)

    config = ConfigParser.RawConfigParser(defaults=
    {
        'iSightRemoteImportUrl': 'https://api.isightpartners.com',
        'iSightRemoteImportDaysBack': 80,
        'iSightDefaultScore': 50,
        'iSightFeedName': 'isightconnector',
        'iSightGetReports': 'false'
    }
    )
    config.read(configpath)

    if not config.has_section('cb-isight'):
        raise FatalError("Config File must have cb-isight section")

    for option in ['iSightRemoteImportPublicKey', 'iSightRemoteImportPrivateKey', 'carbonblack_server_token']:
        if not config.has_option('cb-isight', option):
            raise FatalError("Config file not complete: missing option {0:s}".format(option))

    api_key = config.get("cb-isight", "iSightRemoteImportPublicKey")
    sec_key = config.get("cb-isight", "iSightRemoteImportPrivateKey")
    days_back = config.getint("cb-isight", "iSightRemoteImportDaysBack")
    api_route = config.get("cb-isight", "iSightRemoteImportUrl")
    default_score = config.get("cb-isight", "iSightDefaultScore")
    feed_name = config.get("cb-isight", "iSightFeedName")
    read_reports = config.getboolean("cb-isight", "iSightGetReports")

    if config.has_option('cb-isight', 'https_proxy'):
        os.environ['HTTPS_PROXY'] = config.get('cb-isight', 'https_proxy')
        os.environ['no_proxy'] = '127.0.0.1,localhost'

    isight_bridge = Bridge(api_route, api_key, sec_key)
    if read_reports:
        reports = isight_bridge.perform(days_back)
    else:
        reports = isight_bridge.perform_iocs(days_back)

    cb_reports = []
    for report in reports:
        cb_id = 'isight-%s' % report['id']
        feed_entry = dict((k, report[k]) for k in ('title', 'link', 'iocs', 'timestamp'))
        feed_entry['id'] = cb_id
        feed_entry['score'] = default_score
        cb_reports.append(feed_entry)

    feed = CbFeed(generate_feed_metadata(feed_name), cb_reports)
    raw_feed_data = feed.dump()

    if export_mode:
        print raw_feed_data
    else:
        with NamedTemporaryFile(dir=CB_ISIGHT_ROOT, delete=False) as fp:
            fp.write(raw_feed_data)
        destination_filename = os.path.join(CB_ISIGHT_ROOT, 'isight_feed.json')
        _logger.info("Creating iSIGHT feed at {0:s}".format(destination_filename))
        os.rename(fp.name, destination_filename)
        os.chmod(destination_filename, 0755)

        if config.has_option('cb-isight', 'carbonblack_server_url'):
            local_cb_server = config.get('cb-isight', 'carbonblack_server_url')
        else:
            local_cb_server = 'https://127.0.0.1'

        c = connect_local_cbapi(local_cb_server, config.get('cb-isight', 'carbonblack_server_token'))
        feed_id = c.feed_get_id_by_name(feed_name)
        if not feed_id:
            _logger.info("Creating iSIGHT feed for the first time")
            c.feed_add_from_url("file://" + CB_ISIGHT_ROOT + '/isight_feed.json', True, False, False)

        # force a synchronization
        c.feed_synchronize(feed_name)


def generate_feed_metadata(feed_name):
    """
    return a dictionary of feed information
    this is feed 'metadata' - the description of the feed, and not the feed contents
    """

    feed = {"name": feed_name, "display_name": "iSIGHT Partners feed",
            "summary": "This is the Carbon Black-iSIGHT connector v2.0",
            "tech_data": "There are no requirements to share any data with Carbon Black to receive this feed."
                         "  The underlying IOC data is provided by iSIGHT Partners",
            "provider_url": "http://www.isightpartners.com/", "icon": "/usr/share/cb/integrations/isight/isight.png"}

    return CbFeedInfo(**feed)


def build_cli_parser():
    parser = argparse.ArgumentParser(description="Carbon Black - iSIGHT integration script")

    parser.add_argument("-c", "--config", action="store", dest="configpath",
                        help="location of iSIGHT integration config file",
                        default="/etc/cb/integrations/isight/isight.config")
    parser.add_argument("-t", "--test", action="store_true", default=False, dest="test_mode",
                        help="Test to ensure that the API credentials are correct")
    parser.add_argument("-e", "--export", action="store_true", default=False, dest="export_mode",
                        help="Output the proposed feed to stdout; do not update feed.")
    parser.add_argument('--version', action='version', version=__version__)

    return parser


def main():
    parser = build_cli_parser()
    opts = parser.parse_args()

    try:
        runner(opts.configpath, opts.export_mode)
    except Exception:
        sys.stderr.write(traceback.format_exc() + '\n')


if __name__ == '__main__':
    sys.exit(main())
