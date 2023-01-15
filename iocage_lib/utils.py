import pathlib
import six

from ctypes import CDLL
from ctypes.util import find_library
from iocage_lib.ioc_exceptions import ValidationFailed


def safe_extractall(t_file, path=".", members=None, *,
                    numeric_owner=False):
    def is_within_directory(directory, target):
        abs_directory = directory.resolve()
        abs_target = target.resolve()
        prefix = os.path.commonprefix([abs_directory, abs_target])
        return prefix == abs_directory

    stem_path = pathlib.Path(path)
    for member in t_file.getmembers():
        member_path = stem_path.joinpath(member.name)
        if not is_within_directory(stem_path, member_path):
            raise ValidationFailed(
                    "Attempted Path Traversal in Tar File")
    t_file.extractall(path, members, numeric_owner=numeric_owner)


def load_ctypes_library(name, signatures):
    library_name = find_library(name)
    if not library_name:
        raise ImportError('No library named %s' % name)
    lib = CDLL(library_name, use_errno=True)
    # Add function signatures
    for func_name, signature in signatures.items():
        function = getattr(lib, func_name, None)
        if function:
            arg_types, restype = signature
            function.argtypes = arg_types
            function.restype = restype
    return lib


def ensure_unicode_str(value):
    if not isinstance(value, six.text_type):
        value = value.decode()
    return value
