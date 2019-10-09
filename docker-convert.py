#!/usr/bin/env python

import argparse
import base64
import binascii
import datetime
import ecdsa
import hashlib
import itertools
import json
import logging
import sys
from jwkest import jws, jwk, ecc

log = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', help='v2s1 manifest', required=True)
    parser.add_argument('--config-layer', help='Config layer')
    parser.add_argument('--namespace', help='Namespace', default='myself')
    parser.add_argument('--repository', help='Image name (repository)', default='dummy')
    parser.add_argument('--tag', help='Tag', default='latest')

    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity')

    args = parser.parse_args()
    logLevel = logging.INFO
    if args.verbose > 1:
        logLevel = logging.DEBUG
    log.setLevel(logLevel)

    converter = Converter(args.manifest, args.config_layer, namespace=args.namespace,
                          repository=args.repository, tag=args.tag)
    manif_data = converter.convert()
    print(manif_data)


class Converter:
    EMPTY_LAYER = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"

    def __init__(self, manifest, config_layer, namespace=None, repository=None, tag=None):
        self.namespace = namespace
        self.repository = repository
        self.tag = tag
        self.manifest = json.load(open(manifest))
        self.config_layer = json.load(open(config_layer))
        self.fs_layers = []
        self.history = []

    def convert(self):
        if self.manifest.get("schemaVersion") == 1:
            log.info("Manifest is already schema 1")
            return _jsonDumps(self.manifest)
        log.info("Converting manifest to schema 1")
        name = "%s/%s" % (self.namespace, self.repository)
        self.compute_layers()
        manifest = dict(name=name, tag=self.tag, architecture=self.config_layer['architecture'],
                        schemaVersion=1, fsLayers=self.fs_layers, history=self.history)
        key = jwk.ECKey().load_key(ecc.P256)
        key.kid = getKeyId(key)
        manifData = sign(manifest, key)
        return manifData

    def compute_layers(self):
        # Layers in v2s1 are in reverse order from v2s2
        layers = reversed(self.manifest['layers'])
        config_layer_history = reversed(self.config_layer['history'])
        diff_ids = reversed(self.config_layer['rootfs']['diff_ids'])
        fs_layers = []
        curr_compressed_dig = next(layers)['digest']
        curr_uncompressed_dig = next(diff_ids)
        for curr_hist in config_layer_history:
            if curr_hist.get("empty_layer"):
                layer_id = self.EMPTY_LAYER
                uncompressed_dig = None
            else:
                layer_id = curr_compressed_dig
                uncompressed_dig = curr_uncompressed_dig
                try:
                    curr_compressed_dig = next(layers)['digest']
                    curr_uncompressed_dig = next(diff_ids)
                except StopIteration:
                    curr_compressed_dig = self.EMPTY_LAYER
                    curr_uncompressed_dig = None
            fs_layers.append((layer_id, uncompressed_dig, curr_hist))
        self.fs_layers = [dict(blobSum=x[0]) for x in fs_layers]
        # Compute v1 compatibility
        parent = None
        history_entries = self.history = []

        for i, (compressed_dig, uncompressed_dig, hist) in enumerate(fs_layers):
            dig = hashlib.sha256(compressed_dig.encode("ascii"))
            if uncompressed_dig:
                dig.update(uncompressed_dig.encode("ascii"))
            layer_count = "%06d" % i
            dig.update(layer_count.encode("ascii"))
            layer_id = dig.hexdigest()
            if parent is None:
                config = dict(self.config_layer)
                config.pop("history", None)
                config.pop("rootfs", None)
            else:
                config = dict(created=hist['created'], container_config=dict(Cmd=hist['created_by']))
            if uncompressed_dig is None:
                config['throwaway'] = True
            config['id'] = layer_id
            if parent is not None:
                config['parent'] = parent
            parent = layer_id
            history_entries.append(dict(v1Compatibility=_jsonDumpsCompact(config)))


def _jsonDumps(data):
    return json.dumps(data, indent=3, sort_keys=True, separators=(',', ': '))


def _jsonDumpsCompact(data):
    return json.dumps(data, sort_keys=True,  separators=(',', ':'))


def sign(data, key):
    jdata = _jsonDumps(data)
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    header = dict(alg="ES256", jwk=key.serialize())
    protected = dict(formatLength=len(jdata)-2,
                     formatTail=jws.b64encode_item(jdata[-2:]),
                     time=now)
    _jws = jws.JWS(jdata, **header)
    protectedHeader, payload, signature = _jws.sign_compact([key], protected=protected).split(".")
    signatures = [dict(header=header, signature=signature, protected=protectedHeader)]
    jpay = _jsonDumps(dict(payload=payload))[1:-2]
    jsig = _jsonDumps(dict(signatures=signatures))[1:-2]
    arr = [jdata[:-2], ',', jpay, ',', jsig, jdata[-2:]]
    # Add the signature block at the end of the json string, keeping the
    # formatting
    jdata2 = ''.join(arr)
    return jdata2


def getKeyId(key):
    derRepr = toDer(key)
    shaRepr = hashlib.sha256(derRepr).digest()[:30]
    b32Repr = base64.b32encode(shaRepr).decode()
    return ':'.join(byN(b32Repr, 4))


def toDer(key):
    point = b"\x00\x04" + number2string(key.x, key.curve.bytes) + number2string(key.y, key.curve.bytes)
    der = ecdsa.der
    curveEncodedOid = der.encode_oid(1, 2, 840, 10045, 3, 1, 7)
    return der.encode_sequence(
        der.encode_sequence(ecdsa.keys.encoded_oid_ecPublicKey, curveEncodedOid),
        der.encode_bitstring(point))


def byN(strobj, N):
    it = iter(strobj)
    while True:
        substr = ''.join(itertools.islice(it, N))
        if not substr:
            return
        yield substr


def number2string(num, order):
    # convert to hex
    nhex = "%x" % num
    # Zero-pad to the left so the length of the resulting unhexified string is order
    nhex = nhex.rjust(2 * order, '0')
    return binascii.unhexlify(nhex)


class Error(Exception):
    pass


if __name__ == '__main__':
    sys.exit(main())
