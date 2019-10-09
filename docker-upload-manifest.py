#!/usr/bin/env python

import argparse
import json
import logging
import requests
import sys

log = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', help='Registry address', required=True)
    parser.add_argument('--namespace', help='Namespace', default='myself')
    parser.add_argument('--repository', help='Image name (repository)', default='dummy')
    parser.add_argument('--tag', help='Tag', default='latest')
    parser.add_argument('manifest', action='append', help='Manifest to push (can be repeated)',
                        type=argparse.FileType())
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity')

    args = parser.parse_args()
    logLevel = logging.INFO
    if args.verbose > 1:
        logLevel = logging.DEBUG
    log.setLevel(logLevel)

    uploader = Uploader(registry=args.registry, namespace=args.namespace, repository=args.repository)
    uploader.validateRegistry()
    for mf in args.manifest:
        uploader.upload(mf, args.tag)


class Uploader():
    URL_Base = "v2"

    def __init__(self, *, registry=None, namespace=None, repository=None):
        if '://' not in registry:
            registry = 'http://' + registry
        self.registry = registry
        self.namespace = namespace
        self.repository = repository
        self._session = requests.Session()

    def upload(self, manifest_file, tag):
        name = "%s/%s" % (self.namespace, self.repository)
        url = '%s/manifests/%s' % (name, tag)
        resp = self._put(url, manifest_file.read(), contentType="application/json")
        log.debug("Status code: %d", resp.status_code)
        if resp.status_code != 202:
            raise UploadError(resp.status_code, resp.reason, resp.text)

    def validateRegistry(self, raiseExceptions=False):
        resp = self._get('')
        ret = (resp.status_code == 200)
        if not ret and raiseExceptions:
            raise UploadError("Unable to access registry at %s: %s" % (resp.request.url, resp.reason))
        return ret

    def _head(self, part):
        return self._req('HEAD', part, allowRedirects=True)

    def _get(self, part):
        return self._req('GET', part, allowRedirects=True)

    def _put(self, part, data, contentType=None, headers=None):
        return self._req('PUT', part, data, contentType=contentType, headers=headers)

    def _post(self, part, data=None, contentType=None):
        return self._req('POST', part, data, contentType=contentType)

    def _req(self, method, part, data=None, allowRedirects=False, contentType=None, headers=None):
        func = self._session.request
        if not headers:
            headers = {}
        headers.update(accept='application/json')
        if data is not None:
            if isinstance(data, (dict, list)):
                data = json.dumps(data)
                headers['Content-Type'] = 'application/json'
        if part.startswith(self.registry):
            url = part
        else:
            url = '/'.join([self.registry, self.URL_Base, part.lstrip('/')])
        try:
            return func(method=method, url=url,
                        headers=headers,
                        data=data,
                        verify=False,
                        allow_redirects=allowRedirects)
        except requests.exceptions.RequestException as e:
            raise UploadError("Error: url=%s, method=%s: %s" % (url, method, e))


class Error(Exception):
    pass


class UploadError(Error):
    pass


if __name__ == '__main__':
    sys.exit(main())
