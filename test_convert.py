# flake8: noqa: E501

import docker_convert


class Test:
    def test_convert(self):
        cnv = docker_convert.Converter_s2_to_s1(MANIFEST, CONFIG_LAYER)
        signed_mf = cnv.convert()
        docker_convert.validate_signature(signed_mf)

        empty = dict(blobSum=cnv.EMPTY_LAYER)
        assert [dict(blobSum="sha256:layer1"), empty, empty, empty, dict(blobSum="sha256:base")] == cnv.fs_layers

    def test_compute_layers(self):
        cnv = docker_convert.Converter_s2_to_s1(MANIFEST, CONFIG_LAYER)
        cnv.compute_layers()
        empty = dict(blobSum=cnv.EMPTY_LAYER)
        assert [dict(blobSum="sha256:layer1"), empty, empty, empty, dict(blobSum="sha256:base")] == cnv.fs_layers
        assert [
            {'v1Compatibility': '{"architecture":"amd64","author":"Mihai Ibanescu <mihai.ibanescu@gmail.com>","config":{"Cmd":["/bin/bash"],"Hostname":"decafbad"},"container_config":{"Hostname":"decafbad","Tty":false},"created":"2019-09-05T21:28:52.173079282Z","docker_version":"1.13.1","id":"d7b329ed9d186ff20c25399e848116430ee9b6ae022cb9f3dc3406144ec3685d","parent":"6474547c15d178825c70a42efdc59a88c6e30d764d184b415f32484562803446"}'},
            {'v1Compatibility': '{"container_config":{"Cmd":"/bin/sh -c #(nop)  MAINTAINER Mihai Ibanescu <mihai.ibanescu@gmail.com>"},"created":"2019-09-05T21:28:43.305854958Z","id":"6474547c15d178825c70a42efdc59a88c6e30d764d184b415f32484562803446","parent":"5708420291e0a86d8dc08ec40b2c1b1799117c33fe85032b87227632f70c1018","throwaway":true}'},
            {'v1Compatibility': '{"container_config":{"Cmd":"/bin/sh -c #(nop)  CMD [\\"/bin/bash\\"]"},"created":"2018-03-06T00:48:12.679169547Z","id":"5708420291e0a86d8dc08ec40b2c1b1799117c33fe85032b87227632f70c1018","parent":"9e9220abceaf86f2ad7820ae8124d01223d8ec022b9a6cb8c99a8ae1747137ea","throwaway":true}'},
            {'v1Compatibility': '{"container_config":{"Cmd":"/bin/sh -c #(nop)  LABEL name=CentOS Base Image vendor=CentOS license=GPLv2 build-date=20180302"},"created":"2018-03-06T00:48:12.458578213Z","id":"9e9220abceaf86f2ad7820ae8124d01223d8ec022b9a6cb8c99a8ae1747137ea","parent":"cb48c1db9c0a1ede7c85c85351856fc3e40e750931295c8fac837c63b403586a","throwaway":true}'},
            {'v1Compatibility': '{"container_config":{"Cmd":"/bin/sh -c #(nop) ADD file:FILE_CHECKSUM in / "},"created":"2018-03-06T00:48:12.077095981Z","id":"cb48c1db9c0a1ede7c85c85351856fc3e40e750931295c8fac837c63b403586a"}'},
        ] == cnv.history


MANIFEST = dict(schemaVersion=2, layers=[
    dict(digest="sha256:base"),
    dict(digest="sha256:layer1"),
])

CONFIG_LAYER = dict(
    architecture="amd64",
    author="Mihai Ibanescu <mihai.ibanescu@gmail.com>",
    config=dict(Hostname="decafbad", Cmd=["/bin/bash"]),
    container_config=dict(Hostname="decafbad", Tty=False),
    created="2019-09-05T21:28:52.173079282Z",
    docker_version="1.13.1",
    history=[
        {
            "created": "2018-03-06T00:48:12.077095981Z",
            "created_by": "/bin/sh -c #(nop) ADD file:FILE_CHECKSUM in / "
        },
        {
            "created": "2018-03-06T00:48:12.458578213Z",
            "created_by": "/bin/sh -c #(nop)  LABEL name=CentOS Base Image vendor=CentOS "
            "license=GPLv2 build-date=20180302",
            "empty_layer": True
        },
        {
            "created": "2018-03-06T00:48:12.679169547Z",
            "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/bash\"]",
            "empty_layer": True
        },
        {
            "created": "2019-09-05T21:28:43.305854958Z",
            "author": "Mihai Ibanescu <mihai.ibanescu@gmail.com>",
            "created_by": "/bin/sh -c #(nop)  MAINTAINER Mihai Ibanescu <mihai.ibanescu@gmail.com>",
            "empty_layer": True
        },
        {
            "created": "2019-09-05T21:28:52.173079282Z",
            "author": "Mihai Ibanescu <mihai.ibanescu@gmail.com>",
            "created_by": "/bin/sh -c touch /usr/share/dummy.txt"
        },
    ],
    rootfs={
        "type": "layers",
        "diff_ids": [
            "sha256:uncompressed_base",
            "sha256:uncompressed_layer1"
        ],
    },
)
