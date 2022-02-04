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
import importlib
import logging as log
from iris_interface import IrisInterfaceStatus

from celery import Task, current_app, shared_task

from app.datamgmt.iris_engine.evidence_storage import EvidenceStorage
from app.iris_engine.module_handler.module_handler import get_mod_config_by_name
from app.iris_engine.module_handler.module_handler import register_hook as iris_register_hook

from iris_interface.IrisInterfaceStatus import IIStatus


class IrisPipelineTypes(object):
    """
    Defines the types of pipelines available to Iris and the module
    """
    pipeline_type_update = 'pipeline_update'
    pipeline_type_import = 'pipeline_import'


class IrisModuleTypes(object):
    """
    Defines the types of modules available
    """
    module_pipeline = 'module_pipeline'
    module_processor = 'module_processor'


class IrisModuleInterface(Task):
    """
    Base class of a pluggable module interface
    """
    _module_name = "IrisBaseModule"
    _module_description = "Base model of an Iris Module interface"
    _interface_version = 1.1
    _module_version = 1.0
    _module_type = 'pipeline'   # OR processor
    _pipeline_support = True
    # -- pipeline_info
    # Contains information on the pipeline provided by the module
    # These settings are used to connect the user through the GUI to
    # the module.
    # Set it to {} for processor module types
    _pipeline_info = {
            "pipeline_internal_name": "base_pipeline",
            "pipeline_human_name": "Base Pipeline",         # Display to the users on the GUI
            "pipeline_args" : [                             # Display to the user as fields
                ['example_arg', 'required'],                   # Mandatory field
                ['another_arg', 'optional']                     # Optional field
            ],
            "pipeline_update_support": True,                # Set to true if the pipeline supports updates
            "pipeline_import_support": True                 # Set to true if the pipeline supports imports
    }

    # The below configuration will be proposed to administrators on the GUI
    # to set the parameters of the module. List of JSONs
    _module_configuration = [
        {
            "param_name": "ex_http_proxy",
            "param_human_name": "HTTP Proxy",
            "param_description": "Example HTTP Proxy",
            "default": None,
            "mandatory": False,
            "type": "string"
        },
        {
            "param_name": "ex_https_proxy",
            "param_human_name": "HTTPS Proxy",
            "param_description": "Example HTTPS Proxy",
            "default": None,
            "mandatory": True,
            "type": "string"
        }
    ]

    def __init__(self):
        """
        Init of the module. Checks that the module is well configured
        """

        self._is_ready = False
        self._celery_decorator = None
        self._evidence_storage = EvidenceStorage()
        self._mod_web_config = get_mod_config_by_name(self._module_name).get_data()

        if self._module_name == "IrisBaseModule":
            log.critical("The module cannot be named as IrisBaseModule. Please reconfigure the module")
            return

        if self._pipeline_support:
            if self._module_type == IrisModuleTypes.module_processor:
                log.critical("Modules of type processor can't have pipelines")
                return

            if self._pipeline_info.get("pipeline_update_support"):
                if not self._pipeline_info.get("pipeline_import_support"):
                    log.critical("Logic error in the module pipeline. Update cannot be supported without import.")
                    return

        # Verify that the core functions of the pipeline are present
        # TODO
        log.info("Module has initiated successfully")
        self._is_ready = True

    def auto_configure(self):
        self._evidence_storage = EvidenceStorage()
        self._mod_web_config = get_mod_config_by_name(self._module_name).get_data()

    def internal_configure(self, celery_decorator=None, evidence_storage=None,
                           mod_web_config = None) -> IrisInterfaceStatus:
        """
        DO NOT OVERRIDE.
        Configure the module to be able to use to methods provided by Iris. This data
        is provided by Iris. Do not override this method.
        :param celery_decorator: Celery decorator provided by Iris
        :param evidence_storage: Evidence storage
        :param mod_web_config: Module configuration provided by the admins through the GUI

        :return: IrisModuleInterfaceStatus
        """
        self._celery_decorator = celery_decorator
        self._evidence_storage = evidence_storage
        self._mod_web_config = mod_web_config

        return IrisInterfaceStatus.I2Success

    def get_evidence_storage(self) -> IrisInterfaceStatus:
        """
        DO NOT OVERRIDE.
        Returns an Evidence Storage class instance. This method should not be override.

        :return: IrisInterfaceStatus
        """
        if not self._evidence_storage:
            return IrisInterfaceStatus.I2InterfaceNotReady("Evidence storage not initialized")

        return IrisInterfaceStatus.I2Success(data=self._evidence_storage)

    def get_init_configuration(self):
        """
        DO NOT OVERRIDE.
        Used by IRIS to get the initial configuration fields.
        :return: JSON configuration
        """
        return self._module_configuration

    def get_configuration(self) -> IrisInterfaceStatus:
        """
        DO NOT OVERRIDE.
        Returns the configuration of the module as set on the GUI.
        The configuration is set and checked Iris side. If errors is encountered
        during the configuration check than an IrisInterfaceStatus error is issued.

        To the default configuration of the module is added a section "iris_conf"
        which embeds details on Iris internal configuration that might be needed by the module.
        See documentation for more details.

        :return: IrisInterfaceStatus
        """
        if not self._mod_web_config:
            return IrisInterfaceStatus.I2InterfaceNotReady("Module configuration not retrieved")

        return IrisInterfaceStatus.I2Success(data=self._mod_web_config)

    def get_configuration_dict(self) -> IrisInterfaceStatus:
        """
        Converts the standard configuration passed by IRIS engine in a key:value dictionnary flavor,
        using 'param_name' as a key, and 'value' as... well the value.

        :return IrisInterfaceStatus
        """
        standard_configuration = self.get_configuration()
        if standard_configuration.is_success():
            standard_configuration_data = standard_configuration.get_data()
            if standard_configuration is None:
                return IrisInterfaceStatus.I2Error("IRIS returned empty configuration")
            else:
                try:
                    configuration = {}
                    for param in standard_configuration_data:
                        if param.get('value'):
                            configuration[param.get('param_name')] = param.get('value')
                        else:
                            configuration[param.get('param_name')] = param.get('default')

                    return IrisInterfaceStatus.I2Success(data=configuration)
                except Exception as e:
                    return IrisInterfaceStatus.I2Error("Configuration malformed: {e}".format(e=e))
        else:
            # Just return the error status
            return standard_configuration

    def is_ready(self) -> bool:
        """
        Returns true if the module is ready to be used, false if not
        :return: Bool
        """
        return self._is_ready

    def get_module_type(self) -> str:
        """
        Returns the type of the module. Should be pipeline or processor.

        :return: str
        """
        return self._module_type

    def get_module_name(self) -> str:
        """
        Returns the name of the current module
        :return: str
        """
        return self._module_name

    def get_module_description(self) -> str:
        """
        Returns the description of the current module
        :return: str
        """
        return self._module_description

    def get_module_version(self) -> float:
        """
        Returns the interface version for compatibility check on Iris side
        :return: float
        """
        return self._interface_version

    def get_interface_version(self) -> float:
        """
        Returns the interface version for compatibility check on Iris side
        :return: float
        """
        return self._interface_version

    def is_providing_pipeline(self) -> bool:
        """
        Return true if the module is providing a pipeline, else false.
        This method is present for future extend of the modules of IRIS.
        As of now, every module should provide a pipeline support, else it cannot be used.
        :return: Bool
        """
        return self._pipeline_support

    def pipeline_get_info(self):
        """
        Return the pipeline information needed, as a JSON. The pipeline info should at least contain
        the following keys :
            "pipeline_internal_name": str : Internal name of the pipeline. Usually the human name without spaces
            "pipeline_human_name": str : Human name of the pipeline, which will be display on the GUI
            "pipeline_args" : list : list of arguments that will be offered to the user when using the pipeline
            "pipeline_update_support": True if the pipeline supports update (for future use), else False
            "pipeline_import_support": True if the pipeline supports import, else False. From a logic perspective, this
                should never be set to False.
        :return: json
        """

        return self._pipeline_info

    def pipeline_files_upload(self, base_path, file_handle, case_customer, case_name, is_update) -> IrisInterfaceStatus:
        """
        Handle the files savings. This method notify the module that a user initiated a file(s) upload with the
        pipeline. The module is responsible to save the file, thus the security.
        Needs to save the file with file_handle.save(path)
        :param base_path: Path base where the files should be saved
        :param file_handle: Handle of the file to save
        :param case_customer: Name of the customer
        :param case_name: Name of the case
        :param is_update: True if the call is an update
        :return: IrisModuleInterfaceStatus
        """
        return IrisModuleInterface.return_not_implemented()

    def pipeline_handler(self, pipeline_type, pipeline_data) -> IrisInterfaceStatus:
        """
        Main method for the handler
        :param pipeline_type: Type of the pipeline to handle
        :param pipeline_data: Data to be handled
        :return: IrisModuleInterfaceStatus
        """
        return IrisModuleInterface.return_not_implemented()

    def pipeline_init(self, app_info) -> IrisInterfaceStatus:
        """
        This function is called while Iris initiate, so only ONCE !
        It has to initiate the data needed for future use by the pipeline
        :param app_info: Contains information that might be needed by the module such as DB access
        :return: IrisModuleInterfaceStatus
        """
        return IrisModuleInterface.return_not_implemented()

    @staticmethod
    def return_not_implemented() -> IrisInterfaceStatus:
        """
        Notify Iris that the interface method is not implemented on the module
        :return: Tuple
        """
        return IrisInterfaceStatus.I2InterfaceNotImplemented

    def wrap_task(self, f) -> IrisInterfaceStatus:
        """
        Wrapper around Celery decorator, provided by Iris at runtime
        :param f: Function to be wrapper in Celery decorator
        :return: Decorated function
        """
        if self._celery_decorator:
            try:

                _in = self._celery_decorator(f, bind=True)
                return IrisInterfaceStatus.I2NoError(data=_in)

            except Exception as e:
                return IrisInterfaceStatus.I2UnknownError(message=e.__str__())

        return IrisInterfaceStatus.I2UnknownError(message="Celery decorator unavailable")

    @staticmethod
    def return_success(message: str = None):
        return True, message if message else []

    @staticmethod
    def return_error(message: str = None, code: IrisInterfaceStatus = IrisInterfaceStatus.I2UnknownError):
        return False, message if message else []

    def run(self, pipeline_type, pipeline_data) -> IrisInterfaceStatus:

        ret = self.pipeline_handler(pipeline_type, pipeline_data)
        return IrisInterfaceStatus.I2Success(data=ret)

    def register_hooks(self, module_id: int):
        """
        This method is call by IRIS upon module registration. This method should call register_to_hook for each hook
        the module wishes to register. The module ID provided by IRIS in this method NEED to be provided
        in every call to register_to_hook

        :param module_id: Module ID provided by IRIS
        :return: Nothing
        """
        return IrisInterfaceStatus.I2InterfaceNotImplemented

    @staticmethod
    def register_to_hook(module_id: int, iris_hook_name: str, is_manual_hook: bool = False,
                         manual_hook_name: str = None, retry_on_fail: bool = False, max_retry: int = 0,
                         run_asynchronously: bool = True,
                         wait_till_return: bool = False) -> IrisInterfaceStatus:
        """
        ! DO NOT OVERRIDE !

        Register a new hook into IRIS. The hook_name should be a well-known hook to IRIS. iris_hooks table can be
        queried, or by default they are declared in iris source code > source > app > post_init.

        If is_manual_hook is set, the hook is triggered by user action and not automatically. If set, the iris_hook_name
        should be a manual hook (aka begin with on_manual_trigger_) otherwise an error is raised.

        If run_asynchronously is set (default), the action will be sent to RabbitMQ and processed asynchronously.
        If set to false, the action is immediately done, which means it needs to be quick otherwise the request will be
        pending and user experience degraded.

        If wait_till_return and run_asynchronously are set, IRIS will wait for the feedback of the module. It means
        the request will be pending, so the action need to be quick.

        :param module_id: Module ID to register
        :param iris_hook_name: Well-known hook name to register to
        :param is_manual_hook: Set to true to indicate an action to run upon user trigger
        :param manual_hook_name: The name of the hook displayed in the UI, if is_manual_hook is set
        :param retry_on_fail: Set to true to retry the hook if the module fails
        :param max_retry: Indicates how many time the hook should be retry if the module fails
        :param run_asynchronously: Set to true to queue the module action in rabbitmq
        :param wait_till_return: Set to true to wait for the module data
        :return: IrisInterfaceStatus object
        """
        success, log = iris_register_hook(module_id, iris_hook_name, is_manual_hook, manual_hook_name, retry_on_fail,
                                          max_retry, run_asynchronously, wait_till_return)
        if success:
            return IrisInterfaceStatus.I2Success(message=log)

        return IrisInterfaceStatus.I2Error(message=log)