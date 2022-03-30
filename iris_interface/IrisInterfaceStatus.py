#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import logging as logger


class IIStatusCode(object):
    """
    Defines a standard iris interface status code
    """
    def __init__(self, code: int, message: str):
        self.status_code = code
        self.message = message


class IIStatus(object):
    """
    Defines a standard Iris Interface status return object, which contains an IrisInterfaceStatusCode
    and a undefined data object.
    This object aims to be returned from the module to the Iris module handler, in a unified way.
    """

    def __init__(self, code: int = 0xFFFF,
                 message: str = "Unknown error",
                 data=None,
                 logs=None):

        self.code = code if code else 0xFFFF
        self.message = message if message else "Unknown message {}".format(code)
        self.data = data
        self.logs = logs if logs else []

    def is_success(self):
        return self.code < 0xFF00

    def is_failure(self):
        return self.code >= 0xFF00

    def get_data(self):
        return self.data

    def get_logs(self):
        return self.logs

    def get_message(self):
        return self.message

    def __call__(self, *args, **kwargs):
        if kwargs.get('message'):
            self.message = kwargs.get('message')
        if kwargs.get('code'):
            self.code = kwargs.get('code')
        if kwargs.get('data'):
            self.data = kwargs.get('data')
        if kwargs.get('logs'):
            self.logs = kwargs.get('logs')
        if len(args) == 1 and type(args[0]) == str:
            self.message = args[0]

        return self

    def __bool__(self):
        return self.is_success()


def merge_status(status_1: IIStatus, status_2: IIStatus):
    if status_1 is None:
        return status_2
    if status_2 is None:
        return status_1

    if status_2.is_failure():
        status_1.code = status_2.code

    status_1.data = [status_1.data, status_2.data] if status_1.data else status_2.data
    status_1.message = f"{status_1.message} - {status_2.message}"
    status_1.logs.append(status_2.logs)

    return status_1


# Definition of the Standard Interface Status codes
I2CodeError = 0xFFFE
I2CodeNoError = 0x1
I2CodeSuccess = 0x2

I2UnknownError = IIStatus(0xFFFF, "Unknown error")
I2Error = IIStatus(I2CodeError, "Unspecified error")
I2InterfaceNotImplemented = IIStatus(0xFF00, "Interface function not implemented")
I2UnexpectedResult = IIStatus(0xFF01, "Unexpected result")
I2FileNotFound = IIStatus(0xFF02, "File not found")
I2InterfaceNotReady = IIStatus(0xFF03, "Interface not ready")
I2InterfaceNotInitialized = IIStatus(0xFF04, "Interface not initialized")
I2CriticalError = IIStatus(0xFF05, "Critical error")

I2NoError = IIStatus(I2CodeNoError, "No errors")
I2Success = IIStatus(I2CodeSuccess, "Success")
I2ConfigureSuccess = IIStatus(0x3, "Configured successfully")


class QueuingHandler(logger.Handler):
    """A thread safe logging.Handler that writes messages into a queue object.

       Designed to work with LoggingWidget so log messages from multiple
       threads can be shown together in a single ttk.Frame.

       The standard logging.QueueHandler/logging.QueueListener can not be used
       for this because the QueueListener runs in a private thread, not the
       main thread.

       Warning:  If multiple threads are writing into this Handler, all threads
       must be joined before calling logging.shutdown() or any other log
       destinations will be corrupted.
    """

    def __init__(self, *args, message_queue, celery_task,  **kwargs):
        """Initialize by copying the queue and sending everything else to superclass."""
        logger.Handler.__init__(self, *args, **kwargs)
        self.message_queue = message_queue
        self.celery_task = celery_task

    def emit(self, record):
        """Add the formatted log message (sans newlines) to the queue."""
        self.message_queue.append(self.format(record).rstrip('\n'))
        if self.celery_task.request_stack:
            self.celery_task.update_state(state='PROGRESS',
                                          meta=list(self.message_queue))