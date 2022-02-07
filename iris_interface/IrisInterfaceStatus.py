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

log = logger.getLogger('iris_module_interface')
log.setLevel(logger.INFO)


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
        self.logs = logs

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

        if self.is_failure():
            log.error('Error {}. {}'.format(self.code, self.message))
        else:
            log.info('{}'.format(self.message))

        return self


# Definition of the Standard Interface Status codes
I2UnknownError = IIStatus(0xFFFF, "Unknown error")
I2Error = IIStatus(0xFFFE, "Unknown error")
I2InterfaceNotImplemented = IIStatus(0xFF00, "Interface function not implemented")
I2UnexpectedResult = IIStatus(0xFF01, "Unexpected result")
I2FileNotFound = IIStatus(0xFF02, "File not found")
I2InterfaceNotReady = IIStatus(0xFF03, "Interface not ready")
I2InterfaceNotInitialized = IIStatus(0xFF04, "Interface not initialized")
I2CriticalError = IIStatus(0xFF05, "Critical error")

I2NoError = IIStatus(0x1, "No errors")
I2Success = IIStatus(0x2, "Success")
I2ConfigureSuccess = IIStatus(0x3, "Configured successfully")


class IITaskStatus(IIStatus):
    """
    Defines a standard Iris Task status. This object needs to be return when a task over Celery is used.
    """
    def __init__(self, success, user, initial, logs, data, case_name, imported_files):
        super().__init__()
        self.success = success
        self.user = user
        self.initial = initial
        self.logs = logs
        self.data = data
        self.case_name = case_name
        self.imported_files = imported_files

    def _asdict(self):
        json_obj = {
            'success': self.success,
            'user': self.user,
            'initial': self.initial,
            'logs': self.logs,
            'data': self.data,
            'case_name': self.case_name,
            'imported_files': self.imported_files
        }
        return json_obj

    def merge_task_results(self, new_ret, is_update=False):
        """
        Merge the result of multiple tasks
        :param is_update: Set to true if task is an update
        :param new_ret: Task result to merge
        :return:
        """
        # Set the overall task success at false if any of the task failed
        self.success = new_ret.success and self.success

        # Concatenate the tasks logs to display everything at the end
        self.logs += new_ret.logs

        self.data['is_update'] = is_update


def iit_report_task_failure(user=None, initial=None, logs=None, data=None, case_name=None, imported_files=None):
    """
    Reports a task failure
    :param user: User who started the task
    :param initial: Initial task ID
    :param logs: Log output as a list
    :param data: Returned data
    :param case_name: Name of the case the task was run
    :param imported_files: List of the files processed successfully
    :return: IITaskStatus
    """
    return IITaskStatus(success=False, user=user, initial=initial, logs=logs, data=data,
                        case_name=case_name, imported_files=imported_files)


def iit_report_task_success(user=None, initial=None, logs=None, data=None, case_name=None, imported_files=None):
    """
    Reports a task Success
    :param user: User who started the task
    :param initial: Initial task ID
    :param logs: Log output as a list
    :param data: Returned data
    :param case_name: Name of the case the task was run
    :param imported_files: List of the files processed successfully
    :return: IITaskStatus
    """
    return IITaskStatus(success=True, user=user, initial=initial, logs=logs, data=data,
                        case_name=case_name, imported_files=imported_files)


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