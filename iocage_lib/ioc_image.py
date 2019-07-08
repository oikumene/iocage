# Copyright (c) 2014-2019, iocage
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""iocage export and import module"""
import datetime
import fnmatch
import hashlib
import os
import subprocess as su
import zipfile

import iocage_lib.ioc_common
import iocage_lib.ioc_json


class IOCImage(object):
    """export() and import()"""

    def __init__(self, callback=None, silent=False):
        self.pool = iocage_lib.ioc_json.IOCJson().json_get_value("pool")
        self.iocroot = iocage_lib.ioc_json.IOCJson(
            self.pool).json_get_value("iocroot")
        self.date = datetime.datetime.utcnow().strftime("%F")
        self.callback = callback
        self.silent = silent

    def export_jail(self, uuid, path):
        """Make a recursive snapshot of the jail and export to a file."""
        images = f"{self.iocroot}/images"
        name = f"{uuid}_{self.date}"
        image = f"{images}/{name}"
        export_type, jail_name = path.rsplit('/', 2)[-2:]
        image_path = f"{self.pool}/iocage/{export_type}/{jail_name}"
        jail_list = []

        # Looks like foo/iocage/jails/df0ef69a-57b6-4480-b1f8-88f7b6febbdf@BAR
        target = f"{image_path}@ioc-export-{self.date}"

        try:
            iocage_lib.ioc_common.checkoutput(
                ["zfs", "snapshot", "-r", target], stderr=su.STDOUT)
        except su.CalledProcessError as err:
            msg = err.output.decode('utf-8').rstrip()
            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)

        datasets = su.Popen(
            ["zfs", "list", "-H", "-r", "-o", "name", image_path],
            stdout=su.PIPE,
            stderr=su.PIPE).communicate()[0].decode("utf-8").split()

        for dataset in datasets:
            if dataset.split("/")[-1] == jail_name:
                _image = image
                jail_list.append(_image)
            else:
                image_name = dataset.partition(f"{image_path}")[2]
                name = image_name.replace("/", "_")
                _image = image + name
                jail_list.append(_image)
                target = f"{dataset}@ioc-export-{self.date}"

            # Sending each individually as sending them recursively to a file
            # does not work how one expects.
            try:
                with open(_image, "wb") as export:
                    msg = f"Exporting dataset: {dataset}"
                    iocage_lib.ioc_common.logit(
                        {
                            "level": "INFO",
                            "message": msg
                        },
                        self.callback,
                        silent=self.silent)

                    su.check_call(["zfs", "send", target], stdout=export)
            except su.CalledProcessError as err:
                iocage_lib.ioc_common.logit(
                    {
                        "level": "EXCEPTION",
                        "message": err
                    },
                    _callback=self.callback,
                    silent=self.silent)

        msg = f"\nPreparing zip file: {image}.zip."
        iocage_lib.ioc_common.logit(
            {
                "level": "INFO",
                "message": msg
            },
            self.callback,
            silent=self.silent)

        with zipfile.ZipFile(
                f"{image}.zip",
                "w",
                compression=zipfile.ZIP_DEFLATED,
                allowZip64=True) as final:
            os.chdir(images)

            for jail in jail_list:
                final.write(jail)

        with open(f"{image}.zip", "rb") as import_image:
            digest = hashlib.sha256()
            chunk_size = 10 * 1024 * 1024

            while True:
                chunk = import_image.read(chunk_size)

                if chunk == b'':
                    break

                digest.update(chunk)

            image_checksum = digest.hexdigest()

        with open(f"{image}.sha256", "w") as checksum:
            checksum.write(image_checksum)

        # Cleanup our mess.
        try:
            target = f"{self.pool}/iocage/jails/{uuid}@ioc-export-{self.date}"
            iocage_lib.ioc_common.checkoutput(
                ["zfs", "destroy", "-r", target], stderr=su.STDOUT)

            for jail in jail_list:
                os.remove(jail)

        except su.CalledProcessError as err:
            msg = err.output.decode('utf-8').rstrip()
            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)

        msg = f"\nExported: {image}.zip"
        iocage_lib.ioc_common.logit(
            {
                "level": "INFO",
                "message": msg
            },
            self.callback,
            silent=self.silent)

    def import_jail(self, jail):
        """Import from an iocage export."""
        image_dir = f"{self.iocroot}/images"
        exports = os.listdir(image_dir)
        matches = fnmatch.filter(exports, f"{jail}*.zip")

        if len(matches) > 1:
            msg = f"Multiple images found for {jail}:"

            for j in sorted(matches):
                msg += f"\n  {j}"

            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)
        elif len(matches) < 1:
            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": f"{jail} not found!"
                },
                _callback=self.callback,
                silent=self.silent)

        image_target = f"{image_dir}/{matches[0]}"
        uuid, date = matches[0][:-4].rsplit('_', 1)  # :-4 will strip .zip

        import_image = zipfile.ZipFile(image_target, "r")

        for z in import_image.namelist():
            # Split the children dataset out
            z_dataset_type = z.split(f'{date}_', 1)[-1]
            z_dataset_type = z_dataset_type.split(f'{uuid}_', 1)[-1]
            if z_dataset_type == date:
                # This is the parent dataset
                z_dataset_type = uuid
            else:
                z_dataset_type = \
                    f"{uuid}/{z_dataset_type.replace('_', '/')}".rstrip('/')

            cmd = [
                "zfs", "recv", "-F",
                f"{self.pool}/iocage/jails/{z_dataset_type}"
            ]

            msg = f"Importing dataset: {z_dataset_type}"
            iocage_lib.ioc_common.logit(
                {
                    "level": "INFO",
                    "message": msg
                },
                self.callback,
                silent=self.silent)

            dataset = import_image.open(z)
            recv = su.Popen(cmd, stdin=su.PIPE)

            for line in dataset:
                recv.stdin.write(line)

            recv.communicate()

        # Cleanup our mess.
        try:
            target = f"{self.pool}/iocage/jails/{uuid}@ioc-export-{date}"

            iocage_lib.ioc_common.checkoutput(
                ["zfs", "destroy", "-r", target], stderr=su.STDOUT)
        except su.CalledProcessError as err:
            msg = err.output.decode('utf-8').rstrip()
            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)

        # Templates become jails again once imported, let's make that reality.
        jail_json = iocage_lib.ioc_json.IOCJson(
            f'{self.iocroot}/jails/{uuid}', silent=True
        )
        if jail_json.json_get_value('type') == 'template':
            jail_json.json_set_value('type=jail')
            jail_json.json_set_value('template=0', _import=True)

        msg = f"\nImported: {uuid}"
        iocage_lib.ioc_common.logit(
            {
                "level": "INFO",
                "message": msg
            },
            self.callback,
            silent=self.silent)
