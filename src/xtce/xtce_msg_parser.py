"""
Parses messages based on a path such as "/cfs/simlink/apps/to/HK.cmd_cnt"
"""
import math
import struct
from abc import ABC, abstractmethod
from typing import Union, List

from bitarray import bitarray
from bitarray.util import pprint, ba2int, ba2hex, int2ba


try:
    # This import is for unit testing
    from xtce_generator.src.xtce.msg_post_processor import MsgPostProcessor
except ModuleNotFoundError:
    from xtce.msg_post_processor import MsgPostProcessor

try:
    from xtce import xtce, xtce_generator
    from xtce.xtce_generator import XTCEManager
except ModuleNotFoundError:
    from  xtce import xtce
    from  xtce import xtce_generator
    import xtce.xtce_generator.XTCEManager as XTCEManager

from enum import Enum

import logging
import yaml


# FIXME:This function should be moved to a pre-processor.
def extract_bits_from_base_tlm_container(container: dict, comparison: xtce.ComparisonType, container_size: int,
                                         msg_id) -> bitarray:
    extracted_bits = bitarray(endian='big')
    container_key = list(container[XTCEParser.BASE_CONTAINER_KEY].keys())[0]
    comp_value_ref: str = comparison.get_parameterRef()

    # Zero-fill the bitarray up to container size
    for i in range(container_size):
        extracted_bits.insert(i, 0)

    # FIXME:hard-coded for now
    length_offset = get_offset_container(container[XTCEParser.BASE_CONTAINER_KEY][container_key][XTCEParser.PARAMS_KEY],
                                         "ccsds-length")
    length_size = get_param_bit_size(container[XTCEParser.BASE_CONTAINER_KEY][container_key][XTCEParser.PARAMS_KEY],
                                     "ccsds-length")

    msg_id = bytearray(struct.pack('>H', msg_id))
    # TODO: Big/Little endian is inside XTCE
    bits = bitarray(endian='big')
    bits.frombytes(bytes(msg_id))

    # FIXME:For some reason, if we start writing in the middle of the byte it zeroes out the header.
    i = 0
    for bit in bits:
        extracted_bits[i] = bit
        i += 1

    # # TODO: Big/Little endian is inside XTCE
    length_bits = bitarray(endian='big')
    # FIXME:CFS-specific logic should go into a post/pre-processor of some kind
    packet_length = int((container_size - 56) / (8))

    packet_length = struct.pack('>H', packet_length)
    length_bits.frombytes(packet_length)

    i = length_offset
    for bit in length_bits[:length_size]:
        extracted_bits[i] = bit
        i += 1

    return extracted_bits


# FIXME:This function should be moved to a pre-processor.
def extract_bits_from_base_cmd_container(container: dict, comparison: xtce.ComparisonType,
                                         container_size: int, msg_id: int) -> bitarray:
    extracted_bits = bitarray(endian='big')
    container_key = list(container[XTCEParser.BASE_CONTAINER_KEY].keys())[0]

    # Zero-fill the bitarray up to container size
    for i in range(container_size):
        extracted_bits.insert(i, 0)

    # FIXME:hard-coded for now
    length_offset = get_offset_container(container[XTCEParser.BASE_CONTAINER_KEY][container_key][XTCEParser.PARAMS_KEY],
                                         "ccsds-length")
    length_size = get_param_bit_size(container[XTCEParser.BASE_CONTAINER_KEY][container_key][XTCEParser.PARAMS_KEY],
                                     "ccsds-length")

    length_offset += 8

    msg_id = bytearray(struct.pack('>H', msg_id))
    # msg_id[0] = msg_id[0] & 0x0A
    # TODO: Big/Little endian is inside XTCE
    bits = bitarray(endian='big')
    bits.frombytes(bytes(msg_id))

    # FIXME:For some reason, if we start writing in the middle of the byte it zeroes out the header.
    # i = offset
    i = 0
    for bit in bits:
        extracted_bits[i] = bit
        i += 1

    # # TODO: Big/Little endian is inside XTCE
    length_bits = bitarray(endian='big')
    # FIXME:CFS-specific logic should go into a post/pre-processor of some kind
    packet_length = int((container_size - 56) / (8))

    packet_length = struct.pack('>H', packet_length)
    length_bits.frombytes(packet_length)

    i = length_offset
    for bit in length_bits[:length_size]:
        extracted_bits[i] = bit
        i += 1

    return extracted_bits


# TODO:Use these inside the dict.
class IntrinsicDataType(Enum):
    INT = 0
    FLOAT = 1
    STRING = 2
    AGGREGATE = 3
    INTRINSIC = 4


# FIXME:Some App(perhaps XTCE_Communication) should watch a directory since these files will be loaded at runtime.
class XTCEParser:
    # FIXME: Maybe make these keys enums to avoid collisions
    PARAMS_KEY = 'params'
    ARGS_KEY = 'args'
    SPACE_SYSTEM_KEY = 'space_system'
    CONTAINERS_KEY = 'containers'
    COMMANDS_KEY = 'commands'
    BASE_CONTAINER_KEY = 'base_container'
    BASE_COMMAND_KEY = 'base_command'
    BASE_CONTAINER_CRITERIA_KEY = 'criteria'
    BASE_COMNMAND_ARG_ASSIGNMENT_KEY = 'assignment'
    XTCE_OBJ_KEY = 'xtce_obj'
    INTRINSIC_KEY = 'intrinsic'
    ARRAY_TYPE_KEY = 'array_type'
    PARAM_NAME_KEY = 'name'
    ARG_NAME_KEY = 'name'
    AGGREGATE_TYPE = 'aggregate'
    OFFSET_KEY = 'offset'
    SIZE_KEY = 'size'
    STRUCT_SEPARATOR = "."
    HOST_PARAM = 'host'
    COMMAND_CONTAINER = "command_container"

    def __init__(self, xml_files: [str], root_space_system: str, yaml_path: str, log_level: int = logging.WARNING,
                 print_xtce_warnings: bool = False):
        logging.basicConfig()
        self.logger = logging.getLogger("XTCEParser")
        self.logger.setLevel(level=log_level)
        # # Code should be inherited from XTCEManager. See https://github.com/WindhoverLabs/xtce_generator/issues/5
        self.high_level_roots = []
        self.root: xtce.SpaceSystemType
        self.root = xtce.parse(root_space_system, silence=True, print_warnings=print_xtce_warnings)
        self.high_level_roots.append(self.root)
        self.yaml_path = yaml_path
        for file in xml_files:
            self.logger.info(f"Parsing:{file}")
            xtce_obj = xtce.parse(file, silence=True, print_warnings=print_xtce_warnings)
            self.root.add_SpaceSystem(xtce_obj)
            self.high_level_roots.append(xtce_obj)

        names: [str] = []
        self.__namespace_dict = {}
        self.__map_all_spacesystems(self.root, names)
        self.__map_all_containers()
        self.__map_msg_ids()

    def get_msg_ids_at(self, path: str):
        """
        Return the telemetry node(message ids) for the path. If there no telemetry is found for path, None is returned.
        path is expected in the format of "/cfs/simlink/core/cfe/cfe_time"
        """
        if 'telemetry' in self.__namespace_dict[path]:
            return self.__namespace_dict[path]['telemetry']
        else:
            self.logger.warning(f"No telemetry found for {path}")
            return None

    def __get_dict_at_path(self, paths: [str], root_dict: dict):
        dict_partition = root_dict['modules']
        for path in paths:
            if path in dict_partition.keys():
                if 'modules' in dict_partition[path]:
                    dict_partition = dict_partition[path]['modules']
                else:
                    dict_partition = dict_partition[path]
            #         TODO:Check that this is the last node of the path.
            else:
                dict_partition = None
                self.logger.warning(f"Failed to resolve path {'/'.join(paths)} at {path} node")
                break

        return dict_partition

    def __read_yaml(self, yaml_file: str) -> dict:
        yaml_data = yaml.load(open(yaml_file, 'r'),
                              Loader=yaml.FullLoader)
        return yaml_data

    def __map_msg_ids(self):
        """
        Maps all of the message ids to all XTCE telemetry containers.
        It is assumed that the paths in the YAML go after the root XTCE.
        For example; In the path "/cfs/cpd/core/cfe/cfe_es" "/cfs" would be the root of XTCE and
        "/cpd/core/cfe/cfe_es" would be a path in the YAML.
        """
        yaml_dict = self.__read_yaml(self.yaml_path)
        namespace: str
        for namespace in self.__namespace_dict:
            paths = namespace.split(XTCEManager.NAMESPACE_SEPARATOR)[2:]
            path_dict = self.__get_dict_at_path(paths, yaml_dict)
            if path_dict is not None and 'telemetry' in path_dict:
                self.__namespace_dict[namespace]['telemetry'] = path_dict['telemetry']

    def set_qualified_names(self, root: xtce.SpaceSystemType, parent: str):
        # Could be used to simplify the query code when listening/crafting messages
        q_name = ""
        if parent == xtce_generator.XTCEManager.NAMESPACE_SEPARATOR:
            q_name = xtce_generator.XTCEManager.NAMESPACE_SEPARATOR + root.get_name()
        else:
            q_name = parent + xtce_generator.XTCEManager.NAMESPACE_SEPARATOR + root.get_name()
        p: xtce.ParameterType

        root.set_qualified_name(q_name)
        if root.get_TelemetryMetaData() is not None:
            if root.get_TelemetryMetaData().get_ParameterTypeSet() is not None:
                for p in root.get_TelemetryMetaData().get_ParameterSet().get_Parameter():
                    p.set_qualified_name(root.get_qualified_name()
                                         + xtce_generator.XTCEManager.NAMESPACE_SEPARATOR
                                         + p.get_name()
                                         )

            if root.get_TelemetryMetaData().get_ContainerSet() is not None:
                for c in root.get_TelemetryMetaData().get_ContainerSet().get_SequenceContainer():
                    c.set_qualified_name(root.get_qualified_name()
                                         + xtce_generator.XTCEManager.NAMESPACE_SEPARATOR
                                         + c.get_name()
                                         )
        #        TODO:Add qualified names for commands as well
        for s in root.get_SpaceSystem():
            self.set_qualified_names(s, s.get_name())

    def get_spacesystems_map(self) -> dict:
        return self.__namespace_dict

    def __child_names_to_qualified_name(self, names: [str]) -> str:
        return xtce_generator.XTCEManager.NAMESPACE_SEPARATOR + xtce_generator.XTCEManager.NAMESPACE_SEPARATOR.join(
            names)

    def __get_seq_containers_map(self, spacesystem: xtce.SpaceSystemType) -> dict:
        containers_dict = {}
        tlm = spacesystem.get_TelemetryMetaData()
        if tlm is not None:
            container_set = spacesystem.get_TelemetryMetaData().get_ContainerSet()
            if container_set is not None:
                container: xtce.SequenceContainerType
                for container in container_set.get_SequenceContainer():
                    containers_dict[container.get_name()] = {}
                    containers_dict[container.get_name()][self.XTCE_OBJ_KEY] = container
                    # container
                    containers_dict[container.get_name()][XTCEParser.PARAMS_KEY] = self.__get_param_map(container,
                                                                                                        spacesystem)
                    if container.get_BaseContainer() is None:
                        containers_dict[container.get_name()][self.BASE_CONTAINER_KEY] = None
                    else:
                        base_container: xtce.SequenceContainerType = self.__get_container_from_ref(
                            container.get_BaseContainer().containerRef, spacesystem)
                        base_container_spacesystem = self.__get_spacesystem_from_ref(
                            container.get_BaseContainer().containerRef,
                            spacesystem)

                        containers_dict[container.get_name()][self.BASE_CONTAINER_KEY] = self.__get_seq_containers_map(
                            base_container_spacesystem)

                        # Store Criteria Obj in dict
                        containers_dict[container.get_name()][self.BASE_CONTAINER_KEY][
                            self.BASE_CONTAINER_CRITERIA_KEY] = container.get_BaseContainer().get_RestrictionCriteria()
                        containers_dict[container.get_name()][self.BASE_CONTAINER_KEY][
                            self.XTCE_OBJ_KEY] = base_container

        return containers_dict

    def __get_meta_commands_map(self, spacesystem: xtce.SpaceSystemType) -> dict:
        commands_dict = {}
        cmd = spacesystem.get_CommandMetaData()
        if cmd is not None:
            meta_command_set: xtce.MetaCommandSetType
            meta_command_set = spacesystem.get_CommandMetaData().get_MetaCommandSet()
            if meta_command_set is not None:
                meta_command: xtce.MetaCommandType
                for meta_command in meta_command_set.get_MetaCommand():
                    commands_dict[meta_command.get_name()] = {}
                    commands_dict[meta_command.get_name()][self.XTCE_OBJ_KEY] = meta_command
                    # container
                    commands_dict[meta_command.get_name()][self.COMMAND_CONTAINER] = meta_command.get_CommandContainer()
                    commands_dict[meta_command.get_name()][XTCEParser.ARGS_KEY] = self.__get_arg_map(
                        meta_command,
                        spacesystem)
                    if meta_command.get_BaseMetaCommand() is None:
                        commands_dict[meta_command.get_name()][self.BASE_COMMAND_KEY] = None
                    else:
                        base_meta_command: xtce.MetaCommandType = self.__get_command_from_ref(
                            meta_command.get_BaseMetaCommand().get_metaCommandRef(), spacesystem)
                        base_meta_command_spacesystem = self.__get_spacesystem_from_ref(
                            meta_command.get_BaseMetaCommand().get_metaCommandRef(),
                            spacesystem)
                        commands_dict[meta_command.get_name()][
                            self.BASE_COMMAND_KEY] = self.__get_meta_commands_map(
                            base_meta_command_spacesystem)

                        # Store Criteria Obj in dict
                        commands_dict[meta_command.get_name()][self.BASE_COMMAND_KEY][
                            self.BASE_COMNMAND_ARG_ASSIGNMENT_KEY] = meta_command.get_BaseMetaCommand().get_ArgumentAssignmentList()
                        commands_dict[meta_command.get_name()][self.BASE_COMMAND_KEY][
                            self.XTCE_OBJ_KEY] = base_meta_command

        return commands_dict

    def sanitize_type_ref(self, qualified_name: str):
        """
        Convert a qualified name such as "BaseType/string512_LE" to "string512_LE"
        """
        if xtce_generator.XTCEManager.NAMESPACE_SEPARATOR in qualified_name:
            return qualified_name.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]
        else:
            return qualified_name

    def __find_child_match(self, child_name, parent: xtce.SpaceSystemType):
        for c in parent.get_SpaceSystem():
            if c.get_name() == child_name:
                return c

    def __get_relative_space_system(self, root: xtce.SpaceSystemType, name: str) -> xtce.SpaceSystemType:
        if root is not None:
            if root.get_name() == name:
                return root
            for s in root.get_SpaceSystem():
                # self.__get_relative_space_system(root.get_parent(), name)
                if s.get_name() == name:
                    return s
                else:
                    match = self.__find_child_match(name, s)
                    if match is not None:
                        return match

            return self.__get_relative_space_system(root.get_parent(), name)

    def __get_closest_parent(self, parent_name: str, child: xtce.SpaceSystemType) -> Union[xtce.SpaceSystemType, None]:
        if child is None:
            return None
        if parent_name == child.get_name():
            return child
        else:
            for c in child.get_SpaceSystem():
                if c.get_name() == parent_name:
                    return c
        return self.__get_closest_parent(parent_name, child.get_parent())

    def __get_deepest_child(self, parent: xtce.SpaceSystemType, space_system_tokens: [str]):
        if len(space_system_tokens) == 1:
            if space_system_tokens[0] == parent.get_name():
                return parent
        else:
            child_name = space_system_tokens[0]
            for c in parent.get_SpaceSystem():
                if c.get_name() == child_name:
                    self.__get_deepest_child(c, space_system_tokens[1:])
                    break

    def __get_intrinsic_parm_type(self, tlm: xtce.TelemetryMetaDataType, param_type_ref: str) -> Union[
        None, xtce.BaseDataType]:
        result = None
        if tlm.get_ParameterTypeSet() is not None:
            if len(tlm.get_ParameterTypeSet().get_IntegerParameterType()) > 0:
                int_type: xtce.IntegerParameterType
                for int_type in tlm.get_ParameterTypeSet().get_IntegerParameterType():
                    if int_type.get_name() == self.sanitize_type_ref(param_type_ref):
                        result = int_type
            if len(tlm.get_ParameterTypeSet().get_FloatParameterType()) > 0:
                for float_type in tlm.get_ParameterTypeSet().get_FloatParameterType():
                    if float_type.get_name() == self.sanitize_type_ref(param_type_ref):
                        result = float_type
            if len(tlm.get_ParameterTypeSet().get_StringParameterType()) > 0:
                for string_type in tlm.get_ParameterTypeSet().get_StringParameterType():
                    if string_type.get_name() == self.sanitize_type_ref(param_type_ref):
                        result = string_type
            if len(tlm.get_ParameterTypeSet().get_EnumeratedParameterType()) > 0:
                for enum_type in tlm.get_ParameterTypeSet().get_EnumeratedParameterType():
                    if enum_type.get_name() == self.sanitize_type_ref(param_type_ref):
                        result = enum_type
            if len(tlm.get_ParameterTypeSet().get_BooleanParameterType()) > 0:
                for boolean_type in tlm.get_ParameterTypeSet().get_BooleanParameterType():
                    if boolean_type.get_name() == self.sanitize_type_ref(param_type_ref):
                        result = boolean_type
        return result

    def __get_intrinsic_arg_type(self, tlm: xtce.CommandMetaDataType, arg_type_ref: str) -> Union[
        None, xtce.BaseDataType]:
        result = None
        if tlm.get_ArgumentTypeSet() is not None:
            sanitized_ref = self.sanitize_type_ref(arg_type_ref)
            if len(tlm.get_ArgumentTypeSet().get_IntegerArgumentType()) > 0:
                int_type: xtce.IntegerArgumentType
                for int_type in tlm.get_ArgumentTypeSet().get_IntegerArgumentType():
                    if int_type.get_name() == sanitized_ref:
                        result = int_type
            if len(tlm.get_ArgumentTypeSet().get_FloatArgumentType()) > 0:
                for float_type in tlm.get_ArgumentTypeSet().get_FloatArgumentType():
                    if float_type.get_name() == sanitized_ref:
                        result = float_type
            if len(tlm.get_ArgumentTypeSet().get_StringArgumentType()) > 0:
                for string_type in tlm.get_ArgumentTypeSet().get_StringArgumentType():
                    if string_type.get_name() == sanitized_ref:
                        result = string_type
            if len(tlm.get_ArgumentTypeSet().get_EnumeratedArgumentType()) > 0:
                for enum_type in tlm.get_ArgumentTypeSet().get_EnumeratedArgumentType():
                    if enum_type.get_name() == sanitized_ref:
                        result = enum_type
            if len(tlm.get_ArgumentTypeSet().get_BooleanArgumentType()) > 0:
                for boolean_type in tlm.get_ArgumentTypeSet().get_BooleanArgumentType():
                    if boolean_type.get_name() == sanitized_ref:
                        result = boolean_type
        return result

    def __get_spacesystem_from_ref(self, param_ref: str, root: xtce.SpaceSystemType) -> xtce.SpaceSystemType:
        # Only relative references are supported at the moment
        if xtce_generator.XTCEManager.NAMESPACE_SEPARATOR in param_ref:
            space_system_tokens = param_ref.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[:-1]
            parent = self.__get_closest_parent(space_system_tokens[0], root)
            if len(space_system_tokens) == 1:
                return parent
            else:
                return self.__get_deepest_child(parent, space_system_tokens[:1])
        else:
            # This ref is local to this spacesystem
            return root

    def __get_container_from_ref(self, param_ref: str, root: xtce.SpaceSystemType) -> Union[
        xtce.ContainerType, xtce.SequenceContainerType]:
        # Only relative references are supported at the moment
        s: xtce.SpaceSystemType = self.__get_spacesystem_from_ref(param_ref, root)
        c: xtce.SequenceContainerType
        container_name = param_ref.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]
        for c in s.get_TelemetryMetaData().get_ContainerSet().get_SequenceContainer():
            if c.get_name() == container_name:
                return c

    def __get_command_from_ref(self, command_ref: str, root: xtce.SpaceSystemType) -> Union[
        xtce.MetaCommandType]:
        # Only relative references are supported at the moment
        s: xtce.SpaceSystemType = self.__get_spacesystem_from_ref(command_ref, root)
        c: xtce.MetaCommandType
        container_name = command_ref.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]
        for c in s.get_CommandMetaData().get_MetaCommandSet().get_MetaCommand():
            if c.get_name() == container_name:
                return c

    def __get_array_type_param(self, tlm: xtce.TelemetryMetaDataType,
                               param_type_ref: str,
                               spacesystem: xtce.SpaceSystemType) -> list:
        array_type: xtce.ArrayParameterType
        item_param_type = None
        out_array: list = []
        for array_type in tlm.get_ParameterTypeSet().get_ArrayParameterType():
            if array_type.get_name() == self.sanitize_type_ref(param_type_ref):
                dim: xtce.DimensionType
                # TODO:Add support for multi-dimensional array
                for dim in array_type.get_DimensionList().get_Dimension():
                    for i in range(dim.get_StartingIndex().get_FixedValue(),
                                   dim.get_EndingIndex().get_FixedValue() + 1):
                        ref_spacesystem = self.__get_spacesystem_from_ref(array_type.get_arrayTypeRef(),
                                                                          spacesystem)

                        item_param_type = self.__get_intrinsic_parm_type(
                            ref_spacesystem.get_TelemetryMetaData(), array_type.get_arrayTypeRef())
                        if item_param_type is not None:
                            out_array.append(item_param_type)
                        else:
                            # FIXME:Array of structs
                            out_array.append(item_param_type)
                    break

        return out_array


    def __get_array_type_arg(self, cmd: xtce.CommandMetaDataType,
                             arg_type_ref: str,
                             spacesystem: xtce.SpaceSystemType) -> list:
        array_type: xtce.ArrayArgumentType
        item_arg_type = None
        out_array: list = []
        for array_type in cmd.get_ParameterTypeSet().get_ArrayParameterType():
            if array_type.get_name() == self.sanitize_type_ref(arg_type_ref):
                dim: xtce.DimensionType
                # TODO:Add support for multi-dimensional array
                for dim in cmd.get_ArgumentTypeSet().get_ArrayArgumentType():
                    for i in range(dim.get_StartingIndex().get_FixedValue(),
                                   dim.get_EndingIndex().get_FixedValue() + 1):
                        ref_spacesystem = self.__get_spacesystem_from_ref(array_type.get_arrayTypeRef(),
                                                                          spacesystem)

                        item_arg_type = self.__get_intrinsic_arg_type(
                            ref_spacesystem.get_CommandMetaData(), array_type.get_arrayTypeRef())
                        if item_arg_type is not None:
                            out_array.append(item_arg_type)
                        else:
                            # FIXME:Array of structs
                            out_array.append(item_arg_type)
                    break

        return out_array

    def __get_param_type(self, param_type_ref: str, spacesystem: xtce.SpaceSystemType,
                         host_param: str = None, out_dict: dict = {}):
        """
        For now it is assumed that param_type_ref points to a AggregateParameterType
        """
        tlm = spacesystem.get_TelemetryMetaData()
        if tlm is not None:
            if tlm.get_ParameterTypeSet() is not None:
                param_type = self.__get_intrinsic_parm_type(tlm, param_type_ref)
                if param_type is not None:
                    out_dict[XTCEParser.INTRINSIC_KEY] = param_type
                else:
                    if len(tlm.get_ParameterTypeSet().get_ArrayParameterType()) > 0:
                        out_dict[XTCEParser.ARRAY_TYPE_KEY] = self.__get_array_type_param(tlm, param_type_ref, spacesystem)
                        if len(out_dict[XTCEParser.ARRAY_TYPE_KEY]) > 0:
                            return
                    if len(tlm.get_ParameterTypeSet().get_AggregateParameterType()) > 0:
                        # FIXME: Check for intrinsic types and make this function recursive
                        aggregate: xtce.AggregateParameterType
                        for aggregate in tlm.get_ParameterTypeSet().get_AggregateParameterType():
                            if aggregate.get_name() == self.sanitize_type_ref(param_type_ref):
                                member: xtce.MemberType
                                out_dict["fields"] = dict()
                                out_dict[IntrinsicDataType.AGGREGATE] = IntrinsicDataType.AGGREGATE
                                out_dict[XTCEParser.HOST_PARAM] = host_param
                                out_dict[XTCEParser.PARAM_NAME_KEY] = aggregate.get_name()
                                for member in aggregate.get_MemberList().get_Member():
                                    # TODO:Parse fields
                                    out_dict["fields"][member.get_name()] = dict()
                                    out_dict["fields"][member.get_name()][XTCEParser.PARAM_NAME_KEY] = member.get_name()
                                    ref_spacesystem = self.__get_spacesystem_from_ref(member.get_typeRef(), spacesystem)
                                    self.__get_param_type(member.get_typeRef(),
                                                          ref_spacesystem,
                                                          member.get_name(),
                                                          out_dict["fields"][member.get_name()])
                                return

            else:
                for s in spacesystem.get_SpaceSystem():
                    tlm = s.get_TelemetryMetaData()
                    if tlm is not None:
                        if tlm.get_ParameterTypeSet() is not None:
                            param_type = self.__get_intrinsic_parm_type(tlm, param_type_ref)
                            if param_type is not None:
                                out_dict[self.INTRINSIC_KEY] = param_type
                            else:
                                if len(tlm.get_ParameterTypeSet().get_ArrayParameterType()) > 0:
                                    out_dict[XTCEParser.ARRAY_TYPE_KEY] = self.__get_array_type_param(tlm,
                                                                               param_type_ref,
                                                                               spacesystem)
                                    if len(out_dict[XTCEParser.ARRAY_TYPE_KEY]) > 0:
                                        return
                                if len(tlm.get_ParameterTypeSet().get_AggregateParameterType()) > 0:
                                    # FIXME: Check for intrinsic types and make this function recursive
                                    aggregate: xtce.AggregateParameterType
                                    for aggregate in tlm.get_ParameterTypeSet().get_AggregateParameterType():
                                        if aggregate.get_name() == self.sanitize_type_ref(param_type_ref):
                                            member: xtce.MemberType
                                            out_dict["fields"] = dict()
                                            out_dict[IntrinsicDataType.AGGREGATE] = IntrinsicDataType.AGGREGATE
                                            out_dict[XTCEParser.PARAM_NAME_KEY] = aggregate.get_name()
                                            out_dict[XTCEParser.HOST_PARAM] = host_param
                                            for member in aggregate.get_MemberList().get_Member():
                                                out_dict["fields"][member.get_name()] = dict()
                                                out_dict["fields"][member.get_name()][
                                                    XTCEParser.PARAM_NAME_KEY] = member.get_name()

                                                ref_spacesystem = self.__get_spacesystem_from_ref(
                                                    member.get_typeRef(), spacesystem)
                                                self.__get_param_type(member.get_typeRef(),
                                                                      ref_spacesystem,
                                                                      member.get_name(),
                                                                      out_dict["fields"][member.get_name()])
                                            return

    def __get_highest_level_parent(self, s: xtce.SpaceSystemType):
        while s.parent is not None:
            self.__get_highest_level_parent(s.parent)
        return s

    def __get_arg_type(self, arg_type_ref: str, spacesystem: xtce.SpaceSystemType,
                       host_param: str = None, out_dict: dict = {}):
        """
        """
        if spacesystem is None:
            return
        # FIXME:Please cleanup this function. Please.
        cmd = spacesystem.get_CommandMetaData()

        if cmd is not None:
            if cmd.get_ArgumentTypeSet() is not None:
                arg_type = self.__get_intrinsic_arg_type(cmd, arg_type_ref)
                if arg_type is not None:
                    out_dict[XTCEParser.INTRINSIC_KEY] = arg_type
                    return
                if len(cmd.get_ArgumentTypeSet().get_ArrayArgumentType()) > 0:
                    out_dict[XTCEParser.ARRAY_TYPE_KEY] = self.__get_array_type_arg(cmd, arg_type_ref, spacesystem)
                    if len(out_dict[XTCEParser.ARRAY_TYPE_KEY]) > 0:
                        return
                    if len(cmd.get_ArgumentTypeSet().get_AggregateArgumentType()) > 0:
                        # FIXME: Check for intrinsic types and make this function recursive
                        aggregate: xtce.AggregateArgumentType
                        for aggregate in cmd.get_ArgumentTypeSet().get_AggregateArgumentType():
                            if aggregate.get_name() == self.sanitize_type_ref(arg_type_ref):
                                member: xtce.MemberType
                                out_dict["fields"] = dict()
                                out_dict[IntrinsicDataType.AGGREGATE] = IntrinsicDataType.AGGREGATE
                                out_dict[XTCEParser.HOST_PARAM] = host_param
                                out_dict[XTCEParser.ARG_NAME_KEY] = aggregate.get_name()
                                for member in aggregate.get_MemberList().get_Member():
                                    out_dict["fields"][member.get_name()] = dict()
                                    out_dict["fields"][member.get_name()][XTCEParser.ARG_NAME_KEY] = member.get_name()
                                    ref_spacesystem = self.__get_spacesystem_from_ref(member.get_typeRef(), spacesystem)
                                    self.__get_arg_type(member.get_typeRef(),
                                                        ref_spacesystem,
                                                        aggregate.get_name(),
                                                        out_dict["fields"][member.get_name()])
                                return

                for s in spacesystem.get_SpaceSystem():
                    cmd = s.get_CommandMetaData()
                    if cmd is not None:
                        if cmd.get_ArgumentTypeSet() is not None:
                            arg_type = self.__get_intrinsic_arg_type(cmd, arg_type_ref)
                            if arg_type is not None:
                                out_dict[self.INTRINSIC_KEY] = arg_type
                            else:
                                if len(cmd.get_ArgumentTypeSet().get_ArrayArgumentType()) > 0:
                                    out_dict[XTCEParser.ARRAY_TYPE_KEY] = self.__get_array_type_arg(cmd, arg_type_ref,
                                                                                                    spacesystem)
                                    if len(out_dict[XTCEParser.ARRAY_TYPE_KEY]) > 0:
                                        return
                                if len(cmd.get_ArgumentTypeSet().get_AggregateArgumentType()) > 0:
                                    # FIXME: Check for intrinsic types and make this function recursive
                                    aggregate: xtce.AggregateArgumentType
                                    for aggregate in cmd.get_ArgumentTypeSet().get_AggregateArgumentType():

                                        if aggregate.get_name() == self.sanitize_type_ref(arg_type_ref):
                                            member: xtce.MemberType
                                            out_dict["fields"] = dict()
                                            out_dict[IntrinsicDataType.AGGREGATE] = IntrinsicDataType.AGGREGATE
                                            out_dict[XTCEParser.ARG_NAME_KEY] = aggregate.get_name()
                                            out_dict[XTCEParser.HOST_PARAM] = host_param
                                            for member in aggregate.get_MemberList().get_Member():
                                                out_dict["fields"][member.get_name()] = dict()
                                                out_dict["fields"][member.get_name()][
                                                    XTCEParser.ARG_NAME_KEY] = member.get_name()

                                                ref_spacesystem = self.__get_spacesystem_from_ref(
                                                    member.get_typeRef(), spacesystem)
                                                self.__get_arg_type(member.get_typeRef(),
                                                                    ref_spacesystem,
                                                                    aggregate.get_name(),
                                                                    out_dict["fields"][member.get_name()])
                                            return
        self.__get_arg_type(arg_type_ref, self.__get_spacesystem_from_ref(arg_type_ref, spacesystem), host_param,
                            out_dict)

    def __get_param_type_map(self, param_ref: str, spacesystem: xtce.SpaceSystemType):
        parameter_type_dict = dict()
        tlm = spacesystem.get_TelemetryMetaData()
        if tlm is not None:
            if tlm.get_ParameterSet() is not None:
                param: xtce.ParameterType
                for param in tlm.get_ParameterSet().get_Parameter():
                    if param_ref == param.get_name():
                        parameter_type_dict[param.get_name()] = dict()
                        parameter_type_dict[param.get_name()][XTCEParser.PARAM_NAME_KEY] = param.get_name()
                        self.__get_param_type(param.get_parameterTypeRef(), spacesystem, param.get_name(),
                                              parameter_type_dict[param.get_name()])

        return parameter_type_dict

    def __get_param_map(self, container: xtce.SequenceContainerType, spacesystem: xtce.SpaceSystemType):
        entry: xtce.ParameterRefType
        param_dict = {}
        # TODO:Use ordered dict for params
        # In python 3.7+, ordered dicts are law:https://mail.python.org/pipermail/python-dev/2017-December/151283.html
        for entry in container.get_EntryList().get_ParameterRefEntry():
            ref = entry.get_parameterRef()
            # TODO:Query the ParameterSet
            param_dict[ref] = self.__get_param_type_map(ref, spacesystem)
            param_dict[ref][XTCEParser.PARAM_NAME_KEY] = ref
            set_offset(param_dict[ref][ref])

        return param_dict

    def __get_arg_type_map(self, arg_ref: xtce.ArgumentArgumentRefEntryType, command: xtce.MetaCommandType,
                           spacesystem: xtce.SpaceSystemType, argument_type_dict: dict):
        if command is not None:
            if command.get_ArgumentList() is not None and len(command.get_ArgumentList().get_Argument()) > 0:
                arg: xtce.ArgumentType
                for arg in command.get_ArgumentList().get_Argument():
                    if arg_ref.argumentRef == arg.get_name():
                        # FIXME:Passing this dict is redundant as it is overriding the same key that points to an
                        #  empty dict
                        argument_type_dict[arg.get_name()] = dict()
                        argument_type_dict[arg.get_name()][XTCEParser.PARAM_NAME_KEY] = arg.get_name()
                        self.__get_arg_type(arg.get_argumentTypeRef(), spacesystem, arg.get_name(),
                                            argument_type_dict[arg.get_name()])

    def __get_arg_map(self, command: xtce.MetaCommandType, spacesystem: xtce.SpaceSystemType):
        arg_dict = {}
        # TODO:Use ordered dict for params
        # In python 3.7+, ordered dicts are law:https://mail.python.org/pipermail/python-dev/2017-December/151283.html

        # GenerateDS has two separate lists for FixedValue and ArgumentRef Entries, so here
        # we merge them by reading the xml tree directly
        entry_list: [xtce.ArgumentSequenceEntryType] = []
        entry_list_nodes = list(command.get_CommandContainer().get_EntryList().gds_elementtree_node_)
        for entry_node in entry_list_nodes:
            for fixed_node_entry in list(command.get_CommandContainer().get_EntryList().get_FixedValueEntry()):
                if entry_node == fixed_node_entry.gds_elementtree_node_:
                    entry_list.append(fixed_node_entry)
            for arg_node_entry in list(command.get_CommandContainer().get_EntryList().get_ArgumentRefEntry()):
                if entry_node == arg_node_entry.gds_elementtree_node_:
                    entry_list.append(arg_node_entry)

        for entry in entry_list:
            if type(entry) == xtce.ArgumentFixedValueEntryType:
                # For FixedValue obj, we don't have to resolve the type as the object itself has everything we need
                ref = entry.get_name()
                arg_dict[ref] = dict()
                # FIXME: This is horrid I know, but will do it for now to
                # make the FixedValue args consistent in their dict structure with ArgumentRef args.
                arg_dict[ref][ref] = dict()
                arg_dict[ref][ref][XTCEParser.INTRINSIC_KEY] = entry
                arg_dict[ref][ref][XTCEParser.ARG_NAME_KEY] = ref
            elif type(entry) == xtce.ArgumentArgumentRefEntryType:
                ref = entry.get_argumentRef()
                arg_dict[entry.get_argumentRef()] = dict()
                # TODO:Query the ParameterSet
                # FIXME:Passing this dict seems redundant as it is overriding the same key that points to an
                # empty dict
                self.__get_arg_type_map(entry, command, spacesystem, arg_dict[entry.get_argumentRef()])
                arg_dict[ref][XTCEParser.ARG_NAME_KEY] = entry.get_argumentRef()

        return arg_dict

    def __map_all_containers(self):
        """
        Maps all of the containers inside XTCE. {'CI_HK_TLM_MID': {'CI_HK_TLM_MID': {'name': 'CI_HK_TLM_MID',
        'usCmdCnt': {'name': 'usCmdCnt', 'intrinsic': <xtce.xtce.IntegerParameterType object at 0x7f60d08eebe0>},
        'usCmdErrCnt': {'name': 'usCmdErrCnt', 'intrinsic': <xtce.xtce.IntegerParameterType object at
        0x7f60d08eebe0>}, 'padding': {'name': 'padding', 'array_type': [<xtce.xtce.IntegerParameterType object at
        0x7f60d08eebe0>, <xtce.xtce.IntegerParameterType object at 0x7f60d08eebe0>]}, 'IngestMsgCount': {'name':
        'IngestMsgCount', 'intrinsic': <xtce.xtce.IntegerParameterType object at 0x7f60d08eebe0>},
        'IngestErrorCount': {'name': 'IngestErrorCount', 'intrinsic': <xtce.xtce.IntegerParameterType object at
        0x7f60d08eebe0>}}, 'name': 'CI_HK_TLM_MID'}}
        """
        self.__map_tlm_containers()
        self.__map_commands()

    def __map_tlm_containers(self):
        qualified_name: str
        spacesystem: xtce.SpaceSystemType
        for qualified_name in self.__namespace_dict.keys():
            self.logger.info(f"Parsing containers for'{qualified_name}'")
            if self.__namespace_dict[qualified_name][self.SPACE_SYSTEM_KEY] is not None:
                self.__namespace_dict[qualified_name][XTCEParser.CONTAINERS_KEY] = self.__get_seq_containers_map(
                    self.__namespace_dict[qualified_name][self.SPACE_SYSTEM_KEY])

    def __map_commands(self):
        # FIXME:Update for commands
        qualified_name: str
        spacesystem: xtce.SpaceSystemType
        for qualified_name in self.__namespace_dict.keys():
            self.logger.info(f"Parsing containers for'{qualified_name}'")
            if self.__namespace_dict[qualified_name][self.SPACE_SYSTEM_KEY] is not None:
                self.__namespace_dict[qualified_name][XTCEParser.COMMANDS_KEY] = self.__get_meta_commands_map(
                    self.__namespace_dict[qualified_name][self.SPACE_SYSTEM_KEY])

    def __map_all_spacesystems(self, root: xtce.SpaceSystemType, out: list, depth: int = 0):
        """
        Map all of the subsystems names under root.
        """
        # FIXME:This function should be simplified. Don't like how complex this is.
        out = out[:depth]
        out.append(root.get_name())
        spacesystem_qualifiedname = self.__child_names_to_qualified_name(out)
        self.__namespace_dict[spacesystem_qualifiedname] = dict()
        # FIXME: Move these magical keys to const variables
        self.__namespace_dict[spacesystem_qualifiedname][XTCEParser.SPACE_SYSTEM_KEY] = root
        if len(root.get_SpaceSystem()) > 0:
            s: xtce.SpaceSystemType
            for s in root.get_SpaceSystem():
                s.set_parent(root)
                self.__map_all_spacesystems(s, out, depth + 1)
        else:
            spacesystem_qualifiedname = self.__child_names_to_qualified_name(out)
            self.__namespace_dict[spacesystem_qualifiedname] = dict()
            self.__namespace_dict[spacesystem_qualifiedname][XTCEParser.SPACE_SYSTEM_KEY] = root

    def __get_namespace(self, namespace_name: str) -> dict:
        """
        Returns a namespace SpaceSystemType object that has the name of namespace_name.
        :param namespace_name:
        :return:
        """
        namespace_name = namespace_name.rstrip(XTCEManager.NAMESPACE_SEPARATOR)
        return self.__namespace_dict[namespace_name]

    def __query_spacesystem_from_qualified_name(self, qualified_name: str) -> dict:
        """
        Return a SpaceSystemType from a query string such as "/cfs/cpd/apps/px4lib/PX4_VEHICLE_GLOBAL_POSITION_MID.Lat".
        """
        qualified_name = qualified_name.strip(XTCEManager.NAMESPACE_SEPARATOR)
        current_name = ""
        spacesystem = None
        for space_system_name in qualified_name.split(XTCEManager.NAMESPACE_SEPARATOR):
            current_name += XTCEManager.NAMESPACE_SEPARATOR + space_system_name
            if current_name in self.__namespace_dict:
                spacesystem = self.__get_namespace(current_name)

        return spacesystem



    def query_container_from_qualified_name(self, qualified_name: str) -> dict:
        """
        Return a ContainerType from a query string such as "/cfs/cpd/apps/px4lib/PX4_VEHICLE_GLOBAL_POSITION_MID.Lat".
        If the container is not found, None is returned.
        """
        result_container = None
        system: dict = self.__query_spacesystem_from_qualified_name(qualified_name)
        # FIXME: Add error-checking here
        tokens = qualified_name.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)
        if XTCEParser.STRUCT_SEPARATOR in qualified_name:
            container_name = tokens[-1].split(".")[0]
        else:
            container_name = tokens[-1]
        seq_container: xtce.SequenceContainerType
        result_container = system[self.CONTAINERS_KEY][container_name]

        return result_container

    def __getitem__(self, key: str) -> xtce.SpaceSystemType:
        """
        Returns a reference to the namespace with the name of key. If the namespace does not exist, then a new namespace
        with the name of key is created. New namespaces are guaranteed to have an empty CommandMetaDataType object and
        an empty TelemetryMetaDataType object.
        :param key: The name of the namespace.
        :return:
        """
        if not (XTCEManager.NAMESPACE_SEPARATOR in key):
            if key not in self.__namespace_dict:
                key = XTCEManager.NAMESPACE_SEPARATOR + self.root.get_name() + XTCEManager.NAMESPACE_SEPARATOR + key
                # self.__namespace_dict[key] = xtce.SpaceSystemType(name=key)
                # self.__get_namespace(key).set_CommandMetaData(xtce.CommandMetaDataType())
                # self.__get_namespace(key).set_TelemetryMetaData(xtce.TelemetryMetaDataType())
                self.add_namespace(
                    XTCEManager.NAMESPACE_SEPARATOR + self.root.get_name() + XTCEManager.NAMESPACE_SEPARATOR + key)
        else:
            self.__query_spacesystem_from_qualified_name(key)

        return self.__get_namespace(key)


    def find_aggregate_param_type(self, type_name: str, namespace: str) -> Union[xtce.AggregateParameterType, None]:
        """
        Returns a parameter type with the name of type_name. Note that this type_name is the same
        name of a symbol that appears in the database. The namespace refers to the spacesystem inside the XTCE. The
        namespace is the same as the modules in the database. Please note that the type returned is local to the namespace.
        :param type_name:
        :param namespace:
        :return: The  param type object. If the parameter with name of type_name does not exist None is returned.
        """
        out_param_type_ref = None
        if self.namespace_exists(namespace):
            if self[namespace].get_TelemetryMetaData().get_ParameterTypeSet():
                types = [aggregate_name for aggregate_name in
                         self[namespace].get_TelemetryMetaData().get_ParameterTypeSet().get_AggregateParameterType() if
                         aggregate_name.get_name() == type_name]

                # FIXME: There should only be one type in the list.
                if len(types) > 0:
                    out_param_type_ref = types[0]

        return out_param_type_ref


    def namespace_exists(self, namespace_name: str) -> xtce.SpaceSystemType:
        """
        Returns whether or not the namespace exists. Please if you are a user(and not an API author)
        always use this function instead of accessing __namespace_dict directly,
        :param namespace_name:
        :return:
        """
        namespace_name = namespace_name.rstrip(XTCEManager.NAMESPACE_SEPARATOR)
        return namespace_name in self.__namespace_dict

    def query_command_from_qualified_name(self, qualified_name: str) -> dict:
        """
        Return a ContainerType from a query string such as "/cfs/cpd/apps/px4lib/PX4_VEHICLE_GLOBAL_POSITION_MID.Lat".
        If the container is not found, None is returned.
        """
        result_command: xtce.MetaCommandType = None
        system: dict = self.__query_spacesystem_from_qualified_name(qualified_name)
        # FIXME: Add error-checking here
        tokens = qualified_name.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)
        if XTCEParser.STRUCT_SEPARATOR in qualified_name:
            raise Exception(f"No '{XTCEParser.STRUCT_SEPARATOR}' allowed in command names.")

        else:
            command_name = tokens[-1]
        result_command = system[self.COMMANDS_KEY][command_name]

        return result_command

    def query_param_from_paramref(self, param_ref: str) -> Union[xtce.ParameterType]:
        # TODO:Handle the case where are no slashes in param_ref
        result: xtce.ParameterType = None
        s: xtce.SpaceSystemType
        s = self.__query_spacesystem_from_qualified_name(param_ref)[self.SPACE_SYSTEM_KEY]
        param_name = param_ref.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]
        p: xtce.ParameterType
        for p in s.get_TelemetryMetaData().get_ParameterSet().get_Parameter():
            if p.get_name() == param_name:
                result = p
        return result

    def __get_param_name(self, qualified_name: str):
        # FIXME: At the moment nested structs are not supported
        return qualified_name.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]

    def get_value_from_bits(self, value_bits: bitarray, params_map: dict, param_name: str):
        i_type = self.get_param_intrinsic_type(params_map, param_name)
        value = None
        if type(i_type) == xtce.IntegerParameterType:
            value = ba2int(value_bits)
        elif type(i_type) == xtce.FloatParameterType:
            # >> > struct.unpack('f', b)  # native byte order (little-endian on my machine)
            # (1.7230105268977664e+16,)
            # >> > struct.unpack('>f', b)  # big-endian
            # (-109.22724914550781,)
            if i_type.sizeInBits == 32:
                value = struct.unpack('f', value_bits.tobytes())[0]  # little-endian
            elif i_type.sizeInBits == 64:
                value = struct.unpack('d', value_bits.tobytes())[0]  # little-endian
            else:
                # FIXME:Shold not happen.
                pass

        elif type(i_type) == xtce.BooleanParameterType:
            value = bool(ba2int(value_bits))  # little-endian

        elif type(i_type) == xtce.StringParameterType:
            value = value_bits.tobytes().decode('utf-8')  # little-endian

        elif type(i_type) == xtce.EnumeratedParameterType:
            # FIXME:Implement properly
            value = ba2int(value_bits)  # little-endian
            for enum in i_type.get_EnumerationList().get_Enumeration():
                enum: xtce.ValueEnumerationType()

                if enum.get_value() == value:
                    value = enum.get_label()

        # elif type(i_type) == list:
        #     value = []
        #     value = ba2int(value_bits)
        #     for item in i_type:
        #         value.append(item)
        return value

    def validate_packet(self, packet: bytes, path: str, ):
        """
        Returns the value inside of the packet that path points to, but only if packet is valid.
        The packet is validated based on XTCE rules such as criteria for containers.
        If the packet is not valid, None is returned.
        """
        value = None
        bits = bitarray(endian='big')
        bits.frombytes(packet)
        # print(f"path:{path}")
        container_map = self.query_container_from_qualified_name(path)
        criteria: xtce.RestrictionCriteriaType
        criteria = container_map[self.BASE_CONTAINER_KEY][self.BASE_CONTAINER_CRITERIA_KEY]
        comparison_list: xtce.ComparisonListType
        comparison_list = criteria.get_ComparisonList()
        is_valid = True
        # print("validate_packet**1")
        if len(comparison_list.get_Comparison()) > 0:
            for comparison in comparison_list.get_Comparison():
                v = ValueEvaluator()
                # print("validate_packet**2")
                # print(f"path:{path}")
                # print(f"container_map:{container_map}")
                if v.evaluate(container_map, comparison, packet) is not True:
                    is_valid = False
                    break
        if is_valid:
            # print("validate_packet**3")
            # TODO: Extract endian from the params
            container_bits = bitarray(endian='little')
            container_bits.frombytes(packet)
            base_container_key = list(container_map[self.BASE_CONTAINER_KEY].keys())[0]

            base_container_size = get_bit_size_from_tlm_container(
                container_map[self.BASE_CONTAINER_KEY][base_container_key][XTCEParser.PARAMS_KEY])
            param_name = self.__get_param_name(path)
            param_offset = self.get_offset_aggregate(container_map[XTCEParser.PARAMS_KEY],
                                                param_name)

            param_value_size = get_param_bit_size(
                container_map[XTCEParser.PARAMS_KEY],
                param_name)

            # FIXME: Need to handle the case when the param is an array.
            value_bits = container_bits[
                         base_container_size + param_offset:base_container_size + param_offset + param_value_size]

            value = self.get_value_from_bits(value_bits, container_map[XTCEParser.PARAMS_KEY], param_name)
        # print("validate_packet**4")
        return value

    def craft_tlm_command(self, path: str, args: dict, post_processor: MsgPostProcessor = None) -> bytes:
        """
        Returns a new packet based on path and args. This packet(though queried from XTCE telemetry),
        may be used as a command that can be sent to the vehicle.
        """
        # TODO: Query endian from XTCE
        base_container_bits = bitarray(endian='big')
        # FIXME:There is a bit of an implicit assumption here in that this container maps to a param. Add some error
        #  checking here
        container_map = self.query_container_from_qualified_name(path)
        # TODO: Extract endian from the params
        base_container_key = list(container_map[self.BASE_CONTAINER_KEY].keys())[0]

        base_container_size = get_bit_size_from_tlm_container(
            container_map[self.BASE_CONTAINER_KEY][base_container_key][XTCEParser.PARAMS_KEY])
        container_size = get_bit_size_from_tlm_container(container_map[XTCEParser.PARAMS_KEY])

        container_map = self.query_container_from_qualified_name(path)
        criteria: xtce.RestrictionCriteriaType
        criteria = container_map[self.BASE_CONTAINER_KEY][self.BASE_CONTAINER_CRITERIA_KEY]
        comparison_list: xtce.ComparisonListType
        comparison_list = criteria.get_ComparisonList()

        tlm_item = path
        if '.' in path:
            tlm_item = path.split('.')[0]
        tlm_path_namesapce = xtce_generator.XTCEManager.NAMESPACE_SEPARATOR \
                             + xtce_generator.XTCEManager.NAMESPACE_SEPARATOR.join(
            tlm_item.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[1:-1])

        mids = self.get_msg_ids_at(tlm_path_namesapce)
        if mids is None:
            err_msg = f"Invalid telemetry operational name received:{tlm_item} "
        #     FIXME: raise exception
        msg_name = tlm_item.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]

        if msg_name not in mids:
            err_msg = f"{msg_name} message does not exist."
            #     FIXME: raise exception
        mid = mids[msg_name]

        if len(comparison_list.get_Comparison()) > 0:
            # FIXME:At the moment it is assumed that there is only 1 comparison
            for comparison in comparison_list.get_Comparison():
                base_container_bits = extract_bits_from_base_tlm_container(container_map, comparison,
                                                                           base_container_size + container_size,
                                                                           mid['msgID'])
                break

        payload_bits = base_container_bits.copy()
        param_name = self.__get_param_name(path)
        payload_bytes = bytearray(payload_bits.tobytes())
        current_byte_cursor = int(base_container_size / 8)

        # print(f"container_map[XTCEParser.PARAMS_KEY]:{container_map[XTCEParser.PARAMS_KEY]}")
        # for p in

        for arg in args:
            # FIXME: For bit-addressing, use bitarray and look at issue:https://github.com/WindhoverLabs/xtce_generator/issues/64
            arg_value = arg['value']

            i_type = self.get_param_intrinsic_type(container_map[XTCEParser.PARAMS_KEY], param_name + "." + arg['name'])
            # FIXME:Check byte order
            if type(i_type) == xtce.IntegerParameterType:
                # FIXME:This won't work with partials
                size_in_bytes = int(i_type.get_IntegerDataEncoding().get_sizeInBits() / 8)
                signed = False
                if i_type.get_IntegerDataEncoding().encoding == "twosComplement":
                    signed = True
                bytes_data = int(arg_value).to_bytes(size_in_bytes, 'little', signed=signed)

                for byte in bytes_data:
                    payload_bytes[current_byte_cursor] = byte
                    current_byte_cursor = 1 + current_byte_cursor

            elif type(i_type) == xtce.FloatParameterType:
                # >> > st
                # sruct.unpack('f', b)  # native byte order (little-endian on my machine)
                # (1.7230105268977664e+16,)
                # >> > struct.unpack('>f', b)  # big-endian
                # (-109.22724914550781,)
                # float
                if i_type.get_FloatDataEncoding().get_sizeInBits() == 32:
                    bytes_data = struct.pack('<f', arg_value)
                    # print("FloatParameterType#1")
                # double
                elif i_type.get_FloatDataEncoding().get_sizeInBits() == 64:
                    bytes_data = struct.pack('<d', arg_value)
                    # print(f"FloatParameterType#2:{arg_value}")

                for byte in bytes_data:
                    payload_bytes[current_byte_cursor] = byte
                    current_byte_cursor = current_byte_cursor + 1

            elif type(i_type) == xtce.EnumeratedParameterType:
                for enum in i_type.get_EnumerationList().get_Enumeration():
                    enum: xtce.ValueEnumerationType()
                    if enum.get_value() == arg_value:
                        size_in_bytes = int(i_type.get_IntegerDataEncoding().get_sizeInBits() / 8)
                        signed = False
                        if i_type.get_IntegerDataEncoding().encoding == "twosComplement":
                            signed = True

                        bytes_data = int(arg_value).to_bytes(size_in_bytes, 'little', signed=signed)

                        for byte in bytes_data:
                            payload_bytes[current_byte_cursor] = byte
                            current_byte_cursor = 1 + current_byte_cursor
            elif type(i_type) == xtce.BooleanParameterType:
                size_in_bytes = int(i_type.get_IntegerDataEncoding().get_sizeInBits() / 8)
                bytes_data = int(arg_value).to_bytes(size_in_bytes, 'little')

                for byte in bytes_data:
                    payload_bytes[current_byte_cursor] = byte
                    current_byte_cursor = 1 + current_byte_cursor
            else:
                print(f"type(i_type):{type(i_type)}")
                self.logger.warning(f"No type was found for {param_name + '.' + arg['name']}")
        #         FIXME:Raise exception since we could not find a type and could not craft the message

        msg_packet = bytes(payload_bytes)
        if post_processor is not None:
            msg_packet = post_processor.process(bytes(payload_bytes))

        return msg_packet

    def __set_arg_assignment(self, argument_assignment_list: xtce.ArgumentAssignmentListType,
                             arg_obj: xtce.NameDescriptionType,
                             arg: str,
                             in_endian: str = 'big') -> Union[bitarray, None]:
        """
        Set the argument to the value passed, if the argument is found returns a bitarray object with
        the value of the argument set.
        Otherwise, return None.
        """
        arg_bits_out = None
        arg_set = False
        for assignment in argument_assignment_list.get_ArgumentAssignment():
            assignment: xtce.ArgumentAssignmentType
            if assignment.get_argumentName() == arg:
                arg_set = True
                # FIXME:Check byte order in XTCE
                if type(arg_obj) == xtce.IntegerArgumentType:
                    arg_obj: xtce.IntegerArgumentType
                    arg_bits_out = int2ba(int(assignment.get_argumentValue()),
                                          length=int(arg_obj.get_IntegerDataEncoding().get_sizeInBits()),
                                          endian=in_endian)
                    break
        if arg_set is False:
            # If the arg has no assignment, then it is zero-filled
            # FIXME:Check byte order in XTCE
            if type(arg_obj) == xtce.IntegerArgumentType:
                arg_obj: xtce.IntegerArgumentType
                arg_bits_out = int2ba(int(0),
                                      length=int(arg_obj.get_IntegerDataEncoding().get_sizeInBits()), endian=in_endian)
        return arg_bits_out

    def craft_command(self, path: str, args: dict, post_processor: MsgPostProcessor = None) -> bytes:
        """
        Returns a new packet based on path and args.
        """
        value = None
        # TODO: Query endian from XTCE
        base_command_bits = bitarray(endian='big')
        # FIXME:There is a bit of an implicit assumption here in that this container maps to a param. Add some error
        # checking here
        command_map = self.query_command_from_qualified_name(path)
        base_command_key = list(command_map[self.BASE_COMMAND_KEY].keys())[0]

        assignments: xtce.ArgumentAssignmentListType
        argument_assignment_list = command_map[self.BASE_COMMAND_KEY][self.BASE_COMNMAND_ARG_ASSIGNMENT_KEY]
        argument_assignment_list: xtce.ArgumentAssignmentListType

        # FIXME:At the moment we don't check for the "." in the name, but we should since it is not
        # compliant to spec.
        # https://github.com/WindhoverLabs/xtce_generator/issues/62
        # if '.' in path:
        #     cmd_item = path.split('.')[0]

        current_bit_cursor = 0

        for arg in command_map[self.BASE_COMMAND_KEY][base_command_key][XTCEParser.ARGS_KEY]:
            # Assumes the args are in order for now
            arg_dict = command_map[self.BASE_COMMAND_KEY][base_command_key][XTCEParser.ARGS_KEY][arg][arg]
            arg_bits = bitarray()
            if XTCEParser.INTRINSIC_KEY in arg_dict:
                arg_obj = arg_dict[XTCEParser.INTRINSIC_KEY]
                if type(arg_obj) == xtce.ArgumentFixedValueEntryType:
                    arg_obj: xtce.ArgumentFixedValueEntryType
                    arg_bits = int2ba(int(arg_obj.binaryValue), length=int(arg_obj.sizeInBits), endian='big')
                else:
                    # FIXME:Hard-coded for now. This is because the cmd-code "skips" a bit.
                    #  Use offsets instead from the container(base container).
                    endian = 'big'
                    if arg == "cfs-cmd-code":
                        skipped_bit = int2ba(int(0), length=1, endian='big')
                        base_command_bits += skipped_bit
                        endian = 'big'

                    arg_bits = self.__set_arg_assignment(argument_assignment_list, arg_obj, arg, endian)
            else:
                #  Should not happen as it is assumed that everything is intrinsic
                pass
            base_command_bits += arg_bits
        
        payload_bits = base_command_bits.copy()

        current_bit_cursor = len(payload_bits)

        # This logic is horrid, I know.
        command_args = args[0]["value"]
        for arg in command_args:
            arg_bits = bitarray(endian='little')
            arg_value = command_args[arg]

            arg_dict = command_map[XTCEParser.ARGS_KEY][arg]
            arg_bits = bitarray()
        
            # FIXME: Need to handle the case when the param is an array.
            i_type = arg_dict[arg][XTCEParser.INTRINSIC_KEY]
            # FIXME:Check byte order
            if type(i_type) == xtce.IntegerArgumentType:
                # FIXME:This won't work with partials
                size_in_bytes = int(i_type.get_IntegerDataEncoding().get_sizeInBits() / 8)
                bytes_data = int(arg_value).to_bytes(size_in_bytes, 'little')
        
                arg_bits.frombytes(bytes_data)
                for bit in arg_bits:
                    payload_bits.append(bit)
                    current_bit_cursor += 1
        
            elif type(i_type) == xtce.FloatArgumentType:
                # >> > struct.unpack('f', b)  # native byte order (little-endian on my machine)
                # (1.7230105268977664e+16,)
                # >> > struct.unpack('>f', b)  # big-endian
                # (-109.22724914550781,)
                arg_bits.frombytes(bytes(bytearray(struct.pack('f', arg_value))))
        
                for bit in arg_bits:
                    payload_bits.append(bit)
                    current_bit_cursor += 1
        
                value = struct.pack('f', arg_value)[0]  # little-endian
            #
            #     elif type(i_type) == xtce.BooleanParameterType:
            #         pass
            #         # value = bool(ba2int(value_bits))  # little-endian
            #
            #     elif type(i_type) == xtce.StringParameterType:
            #         pass
            #         # value = value_bits.tobytes().decode('utf-8')  # little-endian
            #
            elif type(i_type) == xtce.EnumeratedArgumentType:
                # FIXME:Implement properly
                size_in_bytes = int(i_type.get_IntegerDataEncoding().get_sizeInBits() / 8)
                bytes_data = int(arg_value).to_bytes(size_in_bytes, 'little')
                arg_bits.frombytes(bytes_data)
                value = ba2int(arg_bits)  # little-endian
                for enum in i_type.get_EnumerationList().get_Enumeration():
                    enum: xtce.ValueEnumerationType()
        
                    if enum.get_value() == arg_value:
                        value = enum.get_label()
        
                        for bit in arg_bits:
                            payload_bits.append(bit)
                            # payload_bits[current_bit_cursor] = bit
                            current_bit_cursor += 1
        
            elif type(i_type) == List[xtce.BaseDataType]:
                value = []
                for item in i_type:
                    pass
            else:
                logging.warning(f"The packet for {path} is valid, but no type for it was found.")

        

        # FIXME:Implement    using bytearray.

        # param_name = self.__get_param_name(path)

        cmd_bytes = bytearray(payload_bits.tobytes())

        msg_packet = bytes(cmd_bytes)
        if post_processor is not None:
            msg_packet = post_processor.process(bytes(cmd_bytes))

        return msg_packet

    def get_offset_aggregate(self, params, param_name) -> int:
        """"
        It is assumed that the params are sequential.
        """

        # print(f"param_name:{param_name}, params:{params}")
        offset = 0
        if XTCEParser.INTRINSIC_KEY in params:
            if params[XTCEParser.PARAM_NAME_KEY] == param_name:
                offset = params[XTCEParser.OFFSET_KEY] - get_bit_size(params[XTCEParser.INTRINSIC_KEY])

        elif XTCEParser.ARRAY_TYPE_KEY in params and params[XTCEParser.PARAM_NAME_KEY] == param_name:
            for p in params[XTCEParser.ARRAY_TYPE_KEY]:
                # FIXME:This assumes all elements in list are intrinsic
                offset += get_bit_size(p)

        else:
            if type(params) is dict:
                if IntrinsicDataType.AGGREGATE in params:
                    if XTCEParser.STRUCT_SEPARATOR in param_name:
                        name_path = param_name.split(XTCEParser.STRUCT_SEPARATOR)
                        aggregate_name = name_path[0]

                        if aggregate_name == params[XTCEParser.HOST_PARAM]:
                            new_name = XTCEParser.STRUCT_SEPARATOR.join(name_path[1:])
                            for field in params["fields"]:
                                # print(f'params["fields"][field]:{params["fields"][field]}')
                                offset += self.get_offset_aggregate(params["fields"][field], new_name)
                                # print(f"offset:{offset}")
                                if offset > 0:
                                    break
                        else:
                            self.logger.error(f"Could not find aggregate name {aggregate_name}")
                    # else:
                    #     if params[XTCEParser.PARAM_NAME_KEY] == param_name:
                    #         name_path = param_name.split(XTCEParser.STRUCT_SEPARATOR)
                    #         # This is a field. Subscribing to structs is not supported at the moment
                    #         field_name = name_path[-1]
                    #         for field in params["fields"]:
                    #             if field == field_name:
                    #                 break
                    #             offset += get_offset(params["fields"][field], field_name)

                else:
                    for p in params:
                        if type(params[p]) is dict:
                            offset += self.get_offset_aggregate(params[p], param_name)
                            if offset > 0:
                                break
        return offset

    def get_param_intrinsic_type(self, params, param_name) -> Union[xtce.BaseDataType, List[xtce.BaseDataType]]:
        """"
        It is assumed that the params are sequential.
        """
        i_type = None
        # FIXME:Add support for nested structs. Should be pretty easy now.
        if XTCEParser.INTRINSIC_KEY in params and params[XTCEParser.PARAM_NAME_KEY] == param_name:
            # TODO:Handle this better as there may be a param name called "name" in the XTCE
            if params[XTCEParser.PARAM_NAME_KEY] == param_name:
                i_type = params[XTCEParser.INTRINSIC_KEY]

        # FIXME:Might be a good idea to wrap array types as "intrinsic" types as well.
        elif XTCEParser.ARRAY_TYPE_KEY in params and params[XTCEParser.PARAM_NAME_KEY] == param_name:
            i_type = []
            for p in params[XTCEParser.ARRAY_TYPE_KEY]:
                # Replace with array type
                i_type.append(p)
        else:
            if type(params) is dict:
                if IntrinsicDataType.AGGREGATE in params:
                    if XTCEParser.STRUCT_SEPARATOR in param_name:
                        name_path = param_name.split(XTCEParser.STRUCT_SEPARATOR)
                        aggregate_name = name_path[0]

                        # if aggregate_name == params[XTCEParser.HOST_PARAM]:
                        new_name = XTCEParser.STRUCT_SEPARATOR.join(name_path[1:])
                        if XTCEParser.STRUCT_SEPARATOR in new_name:
                            for field in params["fields"]:
                                new_type = self.get_param_intrinsic_type(params["fields"][field], new_name)
                                if new_type is not None:
                                    i_type = new_type
                                    break

                            # nested struct
                        else:
                            # This is a field. Subscribing to structs is not supported at the moment
                            field_name = name_path[-1]
                            for field in params["fields"]:
                                new_type = self.get_param_intrinsic_type(params["fields"][field], field_name)
                                if new_type is not None:
                                    i_type = new_type
                                    break
                                if field == field_name:
                                    # Should not happen
                                    self.logger.error(f"No type for field '{field}' found")
                                    break

                        # else:
                        #     pass
                        #     Should not happen. This will mean either there is a bug in our code or the path is incorrect.
                        #     Throw exception
            for p in params:
                # TODO:Handle this better as there may be a param name called "name" in the XTCE
                if p == param_name:
                    new_type = self.get_param_intrinsic_type(params[p], param_name)
                    if new_type is not None:
                        i_type = new_type
                        break
                else:
                    if type(params[p]) is dict:
                        new_type = self.get_param_intrinsic_type(params[p], param_name)
                        if new_type is not None:
                            i_type = new_type
                            break

        return i_type


class Evaluator(ABC):
    # @abstractmethod
    # def evaluate(self) -> bool:
    pass


def get_bit_size(intrinsic_type: Union[list, xtce.BaseDataType]):
    bit_size = 0
    if isinstance(intrinsic_type, xtce.IntegerParameterType) or isinstance(intrinsic_type, xtce.IntegerArgumentType):
        bit_size = intrinsic_type.get_IntegerDataEncoding().get_sizeInBits()
    elif isinstance(intrinsic_type, list):
        for item in intrinsic_type:
            bit_size += get_bit_size(item)

    elif isinstance(intrinsic_type, xtce.FloatParameterType) or isinstance(intrinsic_type, xtce.FloatArgumentType):
        bit_size += intrinsic_type.get_sizeInBits()

    elif isinstance(intrinsic_type, xtce.BooleanParameterType) or isinstance(intrinsic_type, xtce.BooleanArgumentType):
        # FIXME: It is perfectly legal to have something else other than Integer encoding for boolean types
        bit_size += intrinsic_type.get_IntegerDataEncoding().get_sizeInBits()

    elif isinstance(intrinsic_type, xtce.StringParameterType) or isinstance(intrinsic_type, xtce.StringArgumentType):
        bit_size += intrinsic_type.get_StringDataEncoding().get_SizeInBits().get_Fixed().get_FixedValue()

    elif isinstance(intrinsic_type, xtce.EnumeratedParameterType) or isinstance(intrinsic_type,
                                                                                xtce.EnumeratedArgumentType):
        bit_size += intrinsic_type.get_IntegerDataEncoding().get_sizeInBits()

    elif isinstance(intrinsic_type, xtce.ArgumentFixedValueEntryType):
        bit_size += intrinsic_type.get_sizeInBits()

    return bit_size




def get_offset_container(params, param_name) -> int:
    """"
    It is assumed that the params are sequential.
    """
    offset = 0
    if XTCEParser.INTRINSIC_KEY in params:
        if params[XTCEParser.PARAM_NAME_KEY] != param_name:
            offset = get_bit_size(params[XTCEParser.INTRINSIC_KEY])

    elif XTCEParser.ARRAY_TYPE_KEY in params and params[XTCEParser.PARAM_NAME_KEY] != param_name:
        for p in params[XTCEParser.ARRAY_TYPE_KEY]:
            # FIXME:This assumes all elements in list are intrinsic
            offset += get_bit_size(p)

    else:
        if type(params) is dict:
            for p in params:
                if p == param_name:
                    break
                if type(params[p]) is dict:
                    offset += get_offset_container(params[p], param_name)
    return offset


def set_offset(params, start_offset: int = 0) -> int:
    """"
    It is assumed that the params are sequential.
    """
    offset = 0
    if XTCEParser.INTRINSIC_KEY in params:
        offset = get_bit_size(params[XTCEParser.INTRINSIC_KEY])
        params[XTCEParser.OFFSET_KEY] = offset + start_offset

    elif XTCEParser.ARRAY_TYPE_KEY in params:
        for p in params[XTCEParser.ARRAY_TYPE_KEY]:
            # FIXME:This assumes all elements in list are intrinsic
            offset += get_bit_size(p)

    elif IntrinsicDataType.AGGREGATE in params:
        field_offset = start_offset
        for field in params["fields"]:
            field_offset += set_offset(params["fields"][field], field_offset)
        offset = field_offset - start_offset
    return offset


def get_bit_size_from_tlm_container(params) -> int:
    """"
    It is assumed that the params are sequential.
    """
    offset = 0

    if XTCEParser.INTRINSIC_KEY in params:
        offset = get_bit_size(params[XTCEParser.INTRINSIC_KEY])

    # FIXME:Might be a good idea to wrap array types as "intrinsic" types as well.
    elif XTCEParser.ARRAY_TYPE_KEY in params:
        for p in params[XTCEParser.ARRAY_TYPE_KEY]:
            offset += get_bit_size(p)
    else:
        if type(params) is dict:
            for p in params:
                if type(params[p]) is dict:
                    offset += get_bit_size_from_tlm_container(params[p])
    return offset


def get_bit_size_from_cmd_container(args) -> int:
    """"
    It is assumed that the args are sequential.
    """
    offset = 0

    if XTCEParser.INTRINSIC_KEY in args:
        offset = get_bit_size(args[XTCEParser.INTRINSIC_KEY])

    # FIXME:Might be a good idea to wrap array types as "intrinsic" types as well.
    elif XTCEParser.ARRAY_TYPE_KEY in args:
        for p in args[XTCEParser.ARRAY_TYPE_KEY]:
            offset += get_bit_size(p)
    else:
        if type(args) is dict:
            for p in args:
                if type(args[p]) is dict:
                    offset += get_bit_size_from_cmd_container(args[p])
    return offset


#  FIXME:Add bool flag to know whether you have found the param or not. Or this is a possible solution
#  to having multiple keys with the same name across multiple levels of the dict.
def get_param_bit_size(params, param_name) -> int:
    """"
    It is assumed that the params are sequential.
    """
    size = 0
    # TODO:Handle this better as there may be a param name called "name" in the XTCE
    if XTCEParser.INTRINSIC_KEY in params and params[XTCEParser.PARAM_NAME_KEY] == param_name:
        size = get_bit_size(params[XTCEParser.INTRINSIC_KEY])
    elif XTCEParser.ARRAY_TYPE_KEY in params and params[XTCEParser.PARAM_NAME_KEY] == param_name:
        for p in params[XTCEParser.ARRAY_TYPE_KEY]:
            # FIXME:This assumes all elements in list are intrinsic
            size += get_bit_size(p)
    else:
        if type(params) is dict:
            if IntrinsicDataType.AGGREGATE in params:
                if XTCEParser.STRUCT_SEPARATOR in param_name:
                    name_path = param_name.split(XTCEParser.STRUCT_SEPARATOR)
                    aggregate_name = name_path[0]

                    if aggregate_name == params[XTCEParser.HOST_PARAM]:
                        # if aggregate_name == params[XTCEParser.HOST_PARAM]:
                        new_name = XTCEParser.STRUCT_SEPARATOR.join(name_path[1:])
                        if XTCEParser.STRUCT_SEPARATOR in new_name:
                            for field in params["fields"]:
                                size += get_param_bit_size(params["fields"][field], new_name)
                        else:
                            for field in params["fields"]:
                                size += get_param_bit_size(params["fields"][field], new_name)

                        # nested struct
                else:
                    if params[XTCEParser.PARAM_NAME_KEY] == param_name:
                        name_path = param_name.split(XTCEParser.STRUCT_SEPARATOR)
                        # This is a field. Subscribing to structs is not supported at the moment
                        field_name = name_path[-1]
                        for field in params["fields"]:
                            size += get_param_bit_size(params["fields"][field], field_name)
                            if field == field_name:
                                break

            else:
                for p in params:
                    # TODO:Handle this better as there may be a param name called "name" in the XTCE
                    if type(params[p]) is dict:
                        size += get_param_bit_size(params[p], param_name)
                    if p == param_name:
                        break
    return size


# TODO:Move this to a different module.
# This will allow us to decouple ourselves from a specific protocol such as CCSDS, Mavlink.
class ValueEvaluator(Evaluator):
    def evaluate(self, container: dict, comparison: xtce.ComparisonType, packet: bytes) -> bool:
        valid = False
        # print("evaluate#1")
        container_key = list(container[XTCEParser.BASE_CONTAINER_KEY].keys())[0]
        # FIXME: The value of the comparison won't always be an int.
        comp_value = int(comparison.get_value())
        comp_value_ref: str = comparison.get_parameterRef()
        if xtce_generator.XTCEManager.NAMESPACE_SEPARATOR in comp_value_ref:
            comp_value_ref = comp_value_ref.split(xtce_generator.XTCEManager.NAMESPACE_SEPARATOR)[-1]

        offset = get_offset_container(container[XTCEParser.BASE_CONTAINER_KEY][container_key][XTCEParser.PARAMS_KEY],
                                      comp_value_ref)

        value_size = get_param_bit_size(container[XTCEParser.BASE_CONTAINER_KEY][container_key][XTCEParser.PARAMS_KEY],
                                        comp_value_ref)
        
        # print(f"comp_value_ref:{comp_value_ref}")

        # TODO: Big/Little endian is inside XTCE
        bits = bitarray(endian='big')
        bits.frombytes(packet)

        extracted_bits = bits[offset:offset + value_size]
        val = ba2int(extracted_bits)
        # print("evaluate#2")
        # print(f"comp_value:{comp_value}")
        # print(f"val:{val}")

        if comp_value == val:
            # print("evaluate#3")
            valid = True
        return valid
