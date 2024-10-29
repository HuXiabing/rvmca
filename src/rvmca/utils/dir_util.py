# MIT License
#
# Copyright (c) 2024 DehengYang (dehengyang@qq.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import glob
import os
from pathlib import Path

from loguru import logger


def get_cur_dir(file_name):
    """
    file_name: __file__
    """
    cur_dir = os.path.dirname(os.path.abspath(file_name))
    return cur_dir


def get_files_by_suffix(dst_dir, suffix):
    files = glob.glob(f"{dst_dir}/**/*{suffix}", recursive=True)
    return sorted(files)


def get_file_names_by_suffix(dst_dir, suffix, recursive=False):
    if recursive:
        files = glob.glob(f"{dst_dir}/**/*{suffix}", recursive=True)
    else:
        files = glob.glob(f"{dst_dir}/*{suffix}", recursive=False)
    file_names = []
    for file in files:
        file_name = Path(file).name
        file_names.append(file_name)
    file_names.sort()
    return file_names


def get_folder_size(folder_path, unit='mb', enable_logging=True):
    """
    https://stackoverflow.com/questions/1392413/calculating-a-directorys-size-using-python
    """
    assert os.path.exists(folder_path)

    total_size = 0
    if os.path.isfile(folder_path):
        total_size += os.path.getsize(folder_path)
    else:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                # skip if it is symbolic link
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)

    _kB = 1024
    # _suffixes = 'B', 'kB', 'MB', 'GB', 'PB'
    KB = total_size / _kB ** 1
    MB = total_size / _kB ** 2
    GB = total_size / _kB ** 3

    if unit == 'kb':
        total_size = KB
    elif unit == 'mb':
        total_size = MB
    elif unit == 'gb':
        total_size = GB
    else:
        raise Exception

    if enable_logging:
        logger.info("size of {}: {:.2f}kb, {:.2f}mb, {:.2f}gb".format(folder_path, KB, MB, GB))

    return total_size


def mk_dir_from_file_path(file_path):
    # assert os.path.isfile(file_path), f"{file_path} is not a file"
    if isinstance(file_path, Path):
        dir_path = file_path.parent
    else:
        dir_path = file_path.rsplit(os.sep, 1)[0]
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def mk_dir_from_dir_path(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
