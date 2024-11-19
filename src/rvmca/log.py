# MIT License
#
# Copyright (c) 2023 Xuezheng (xuezhengxu@126.com)
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

"""Logging"""

import pprint
import sys

from loguru import logger

LOG_LEVELS = [
    'DEBUG',
    'INFO',
    'WARNING',
    'ERROR'
]

LOG_LEVEL = 'DEBUG'

# set the debug level here
logger.remove()
logger.add(sys.stderr)


def level_checker(func):
    # a decorator for checking the log level
    def wrapper(*args, **kwargs):
        if LOG_LEVELS.index(LOG_LEVEL) <= LOG_LEVELS.index(func.__name__):
            func(*args, **kwargs)

    return wrapper


def _format(obj, comments):
    return ('\n' + (comments + '\n') if comments else '') + pprint.pformat(obj)


@level_checker
def DEBUG(obj, comments=''):
    logger.opt(depth=1).debug(_format(obj, comments))


@level_checker
def INFO(obj, comments=''):
    logger.opt(depth=1).info(_format(obj, comments))


@level_checker
def WARNING(obj, comments=''):
    logger.opt(depth=1).warning(_format(obj, comments))


@level_checker
def ERROR(obj, comments=''):
    logger.opt(depth=1).error(_format(obj, comments))
