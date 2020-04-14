#-------------------------------------------------------------------------------
#
#  Auxiliary middle-ware classes
#
# Project: EOxServer - django-allauth integration.
# Authors: Martin Paces <martin.paces@eox.at>
#
#-------------------------------------------------------------------------------
# Copyright (C) 2016 EOX IT Services GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies of this Software or works derived from this Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-------------------------------------------------------------------------------
# pylint: disable=missing-docstring, no-self-use, unused-argument

from logging import getLogger, INFO, WARNING, ERROR, LoggerAdapter
from django.contrib.auth import logout

LOGGER = getLogger("access")


def get_remote_addr(request):
    """ Extract remote address from the Django HttpRequest """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.partition(',')[0]
    return request.META.get('REMOTE_ADDR')


def get_username(user):
    """ Extract username of the authenticated user or return None
    """
    return user.username if user and user.is_authenticated else None


class AccessLoggerAdapter(LoggerAdapter):
    """ Logger adapter adding extra fields required by the access logger. """

    def __init__(self, logger, username=None, remote_addr=None, **kwargs):
        super().__init__(logger, {
            "remote_addr": remote_addr if remote_addr else "-",
            "username": username if username else "-",
        })


def access_logging_middleware(get_response):
    # log levels are set via the  `log_access` decorator
    log_level_authenticated = getattr(
        get_response, 'log_level_auth', INFO
    )
    log_level_unauthenticated = getattr(
        get_response, 'log_level_unauth', INFO
    )

    def get_log_level(status_code, is_authenticated):
        if status_code < 400:
            if is_authenticated:
                return log_level_authenticated
            return log_level_unauthenticated
        if status_code < 500:
            return WARNING
        return ERROR

    def middleware(request):
        logger = AccessLoggerAdapter(
            logger=LOGGER,
            username=get_username(request.user),
            remote_addr=get_remote_addr(request),
        )
        if request.user.is_authenticated:
            type_, level = "A", getattr(get_response, 'log_level_auth', INFO)
        else:
            type_, level = "N", getattr(get_response, 'log_level_unauth', INFO)
        logger.log(level, "%s %s %s", type_, request.method, request.path)

        response = get_response(request)
        """ Log response status. """
        # Warn in case of an error.
        logger.log(
            get_log_level(response.status_code, request.user.is_authenticated),
            "R %s %s %s %s ", request.method, request.path, response.status_code,
            response.reason_phrase,
        )
        return response

    return middleware


def inactive_user_logout_middleware(get_response):

    def middleware(request):
        if request.user.is_authenticated and not request.user.is_active:
            logout(request)
        return get_response(request)

    return middleware
