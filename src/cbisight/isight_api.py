import hashlib
import hmac
import logging
import requests
import email
import urllib
import time
import copy

_logger = logging.getLogger(__name__)


class ISightAPIError(Exception):
    pass


class ISightAPI(object):
    """
    Helper class for talking to iSIGHT Partners remote API.
    """
    @staticmethod
    def from_config(config):
        return ISightAPI(   config.iSightRemoteImportUrl,
                            config.iSightRemoteImportPublicKey,
                            config.iSightRemoteImportPrivateKey)

    output_formats = {
        'json': 'application/json',
        'xml': 'text/xml',
        'html': 'text/html',
        'pdf': 'application/pdf',
        'stix': 'application/stix',
        'csv': 'text/csv',
        'snort': 'application/snort',
        'zip': 'application/zip'
    }

    def __init__(self, base_url, api_key, secret_key):
        self.base_url = base_url
        self.api_key = api_key
        self.secret_key = secret_key
        self.accept_version = '2.0'

        self.headers = {
            'X-App-Name'    : 'cb-isight-partner-api',
            'X-Auth'		: api_key,
            'Accept-Version': self.accept_version
        }

    def _send_request(self, endpoint, accept_mime_type='application/json', params=None):
        # format headers
        time_stamp = email.Utils.formatdate(localtime=True)

        # format params properly
        # see http://www.isightpartners.com/doc/sdk-bp-docs/#/url_encoding
        query = endpoint

        # params is expected to be a dictionary of (key, value) pairs
        if params:
            qs = []
            for param in params.keys():
                qs.append("{0:s}={1:s}".format(urllib.quote(unicode(param).encode('utf-8'), safe=''),
                                               urllib.quote(unicode(params[param]).encode('utf-8'), safe='')))
            if len(qs):
                query += '?{0:s}'.format('&'.join(qs))

        url = "{0:s}{1:s}".format(self.base_url, query)
        hash_data = query + self.accept_version + accept_mime_type + time_stamp

        headers = copy.deepcopy(self.headers)
        headers['X-Auth-Hash'] = hmac.new(self.secret_key, hash_data, hashlib.sha256).hexdigest()
        headers['Accept'] = accept_mime_type
        headers['Date'] = time_stamp

        _logger.debug("Connecting to remote API with URL '%s' : headers '%s'" % (url, headers))

        return requests.get(url, headers=headers)

    @staticmethod
    def get_then_time(days_back_to_retrieve):
        now = int(time.time())
        return now - days_back_to_retrieve*8600

    def get_i_and_w(self, days_back_to_retrieve, format='csv'):
        """
        Retrieve a CSV file of data of all reports from (now-days_back_to_retrieve) until now.
        """
        resp = self._send_request('/view/indicators',
                                  params={'since': self.get_then_time(days_back_to_retrieve)},
                                  accept_mime_type=ISightAPI.output_formats[format])
        if resp.status_code != 200:
            raise ISightAPIError(resp.content)
        else:
            return resp.content

    def get_iocs(self, days_back_to_retrieve, format='csv'):
        """
        Retrieve a CSV file of all IOCs
        """
        resp = self._send_request('/view/iocs',
                                  params={'since': self.get_then_time(days_back_to_retrieve),
                                          'tagTypes': 'file,network'},
                                  accept_mime_type=ISightAPI.output_formats[format])

        if resp.status_code != 200:
            raise ISightAPIError(resp.content)
        else:
            return resp.content

    def get_report(self, report_id, format='xml'):
        """
        Download a report in a particular format.
        """
        resp = self._send_request('/report/{0:s}'.format(report_id),
                                  accept_mime_type=ISightAPI.output_formats[format])
        if resp.status_code != 200:
            raise ISightAPIError(resp.content)
        else:
            return resp.content

    def test(self):
        resp = self._send_request('/test', accept_mime_type='json')
        if resp.status_code == 200 and resp.json()['success'] == 'true':
            return True
        else:
            return False
