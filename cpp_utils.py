import logging
from functools import partial, lru_cache

import ida_bytes
import ida_hexrays
import ida_name
import ida_typeinf
import ida_nalt
import ida_xref
import ida_idaapi
import idautils
import idc
from ida_idaapi import BADADDR
from . import utils
from .utils import batchmode

VTABLE_KEYWORD = "vtbl"
VTABLE_UNION_KEYWORD = "VTABLES"
VTABLES_UNION_VTABLE_FIELD_POSTFIX = ""
VTABLE_DELIMITER = "__"
VTABLE_POSTFIX = "_vtbl"
VTABLE_FIELD_NAME = "__vftable"  # Name For vtable * field
VTABLE_INSTANCE_DELIMITER = VTABLE_DELIMITER
VTABLE_INSTANCE_KEYWORD = "vtable"
VTABLE_INSTANCE_POSTFIX = VTABLE_INSTANCE_DELIMITER + VTABLE_INSTANCE_KEYWORD
MF_BASECLASS = 0x400


def get_vtable_instance_name(class_name, parent_name=None):
    name = class_name + VTABLE_INSTANCE_POSTFIX
    if parent_name is not None:
        name += VTABLE_INSTANCE_DELIMITER + parent_name
    return name


def get_base_member_name(parent_name, offset):
    return "baseclass_%x" % offset


def get_vtable_line(ea, stop_ea=None, ignore_list=None, pure_virtual_name=None):
    if ignore_list is None:
        ignore_list = []
    func_ea = utils.get_ptr(ea)
    if (
        utils.is_func(func_ea)
        and (stop_ea is None or ea < stop_ea)
        and (
            func_ea not in ignore_list
            or (
                pure_virtual_name is not None
                and idc.GetDisasm(ea).endswith(pure_virtual_name)
            )
        )
    ):
        return func_ea, ea + utils.WORD_LEN
    return None, 0


def is_valid_vtable_name(member_name):
    return VTABLE_FIELD_NAME in member_name


def is_valid_vtable_type(member, member_type):
    if member_type.is_ptr():
        struct = utils.deref_struct_from_tinfo(member_type)
        return is_struct_vtable(struct)
    return False


def is_member_vtable(member):
    member_type = utils.get_member_tinfo(member)
    if not member_type or not isinstance(member_type, ida_typeinf.tinfo_t):
        return False
    if not is_valid_vtable_name(member.name):
        return False
    if not is_valid_vtable_type(member, member_type):
        return False
    return True


def is_struct_vtable(struct: ida_typeinf.tinfo_t):
    if struct is None:
        return False
    struct_name = struct.get_type_name()
    return VTABLE_POSTFIX in struct_name


def is_vtables_union(union):
    if union is None:
        return False
    if not union.is_union():
        return False
    union = ida_typeinf.tinfo_t()
    union_name = union.get_type_name()
    return is_vtables_union_name(union_name)


def is_vtables_union_name(union_name):
    return union_name.endswith(VTABLE_UNION_KEYWORD)


def find_vtable_at_offset(struct_ptr: ida_typeinf.tinfo_t, vtable_offset: int):
    current_struct = struct_ptr
    current_offset = 0
    _, member = struct_ptr.get_udm_by_offset(vtable_offset)
    if member is None:
        return None
    parents_vtables_classes = []
    current_offset += member.offset
    while current_offset < vtable_offset and member is not None:
        current_struct = utils.get_member_substruct(member)
        if current_struct is None:
            return
        parents_vtables_classes.append(
            [
                current_struct.get_type_name(),
                vtable_offset - current_offset,
            ]
        )
        _, member = current_struct.get_udm_by_offset(vtable_offset - current_offset)
        if member is None:
            logging.exception(
                "Couldn't find vtable at offset %d for %d",
                vtable_offset - current_offset,
                struct_ptr.get_tid(),
            )
        current_offset += member.offset

    if current_offset != vtable_offset:
        return None

    while member is not None:
        if is_member_vtable(member):
            return member, current_struct, parents_vtables_classes
        current_struct = utils.get_member_substruct(member)
        if current_struct is None:
            return None
        parents_vtables_classes.append(
            [current_struct.get_type_name(), 0]
        )
        index, member = current_struct.get_udm(0)

    return None


def get_class_vtable_struct_name(class_name, vtable_offset_in_class):
    if vtable_offset_in_class == 0:
        return class_name + "_vtbl"
    return "%s_%04X_vtbl" % (class_name, vtable_offset_in_class)


def get_class_vtable_field_name(class_name):
    return VTABLE_FIELD_NAME


def get_class_vtables_union_name(class_name):
    return class_name + VTABLE_DELIMITER + VTABLE_UNION_KEYWORD


def get_class_vtables_field_name(child_name):
    return child_name + VTABLES_UNION_VTABLE_FIELD_POSTFIX


def get_interface_empty_vtable_name():
    return "INTERFACE"


def install_vtables_union(
    class_name: str,
    class_vtable_member: ida_typeinf.udm_t=None,
    vtable_member_tinfo: ida_typeinf.tinfo_t=None,
    offset=0
):
    logging.debug(
        "install_vtables_union(%s, %s, %s)",
        class_name,
        class_vtable_member,
        str(vtable_member_tinfo),
    )
    if class_vtable_member and vtable_member_tinfo:
        old_vtable_sptr = utils.extract_struct_from_tinfo(vtable_member_tinfo)
        old_vtable_class_name = old_vtable_sptr.get_type_name()
    else:
        old_vtable_class_name = get_class_vtable_struct_name(class_name, offset)
        old_vtable_sptr = utils.get_sptr_by_name(old_vtable_class_name)
    vtables_union_name = old_vtable_class_name
    if old_vtable_sptr and (0 != old_vtable_sptr.rename_type(old_vtable_class_name + "_orig")):
        logging.exception(
            f"Failed changing {old_vtable_class_name}->"
            f"{old_vtable_class_name+'_orig'}"
        )
        return -1
    vtables_union_id = utils.get_or_create_struct_id(vtables_union_name, True)
    vtable_member_tinfo = utils.get_typeinf(old_vtable_class_name + "_orig")
    if vtables_union_id == BADADDR:
        logging.exception(
            f"Cannot create union vtable for {class_name}(){vtables_union_name}"
        )
        return -1

    vtables_union = ida_typeinf.tinfo_t(tid=vtables_union_id)
    if not vtables_union:
        logging.exception(f"Could retrieve vtables union for {class_name}")
    if vtable_member_tinfo is not None:
        vtables_union_vtable_field_name = get_class_vtables_field_name(class_name)
    else:
        vtables_union_vtable_field_name = get_interface_empty_vtable_name()
    utils.add_to_struct(
        vtables_union, vtables_union_vtable_field_name, vtable_member_tinfo
    )
    parent_struct = utils.get_sptr_by_name(class_name)
    flag = ida_bytes.FF_STRUCT
    mt = ida_nalt.opinfo_t()
    mt.tid = vtables_union_id
    struct = ida_typeinf.tinfo_t(tid=vtables_union_id)
    struct_size = struct.get_size()
    vtables_union_ptr_type = utils.get_typeinf_ptr(vtables_union_name)
    if class_vtable_member:
        logging.info(f"{class_vtable_member=}, {class_vtable_member=}, {offset=}, {flag=}")
        index, mem = parent_struct.get_udm_by_offset(class_vtable_member.offset)
    else:
        index, mem = parent_struct.get_udm_by_offset(offset)
        if index == -1:
            logging.info(f"{class_name=}, {vtables_union_ptr_type=}, {offset=}, {flag=}")
            index, mem = parent_struct.add_udm(get_class_vtable_field_name(class_name), vtables_union_ptr_type, offset, flag)
    logging.info(f"{mem.name=}")
    if is_valid_vtable_name(mem.name):
        logging.info(f"{index=}, {vtables_union_ptr_type=}, {mem.type=}, {flag=}")
        ret = parent_struct.set_udm_type(index, vtables_union_ptr_type, flag | ida_typeinf.TINFO_DEFINITE)
        logging.info(f"{ret}")
        ret = parent_struct.rename_udm(index, get_class_vtable_field_name(class_name))
        logging.info(f"{ret}")
        utils.refresh_struct(parent_struct)
    return vtables_union


def add_child_vtable(parent_name, child_name, child_vtable_id, offset):
    logging.debug(
        "add_child_vtable (%s, %s, %s)",
        parent_name,
        child_name,
        child_vtable_id,
    )
    parent_struct = utils.get_sptr_by_name(parent_name)
    _, parent_vtable_member = parent_struct.get_udm_by_offset(offset)
    vtable_member_tinfo = utils.get_member_tinfo(parent_vtable_member)
    parent_vtable_struct = utils.get_sptr_by_name(
        get_class_vtable_struct_name(parent_name, offset)
    )
    if parent_vtable_struct is None:
        return None
    pointed_struct = utils.extract_struct_from_tinfo(vtable_member_tinfo)
    logging.debug(f"{str(pointed_struct)=}, {str(parent_vtable_struct)=} {str(parent_vtable_member)=}")
    if (
        (pointed_struct is None)
        or (not is_struct_vtable(pointed_struct))
        or (parent_vtable_struct.get_tid() != pointed_struct.get_tid())
    ):
        parent_vtable_member = None
        logging.debug("Not a struct vtable: %s", str(vtable_member_tinfo))

    # TODO: Check that struct is a valid vtable by name
    if not parent_vtable_struct.is_union():
        logging.debug("%s vtable isn't union -> unionize it!", parent_name)
        parent_vtable_struct = install_vtables_union(
            parent_name, parent_vtable_member, vtable_member_tinfo, offset
        )

    child_vtable_name = ida_typeinf.tinfo_t(tid=child_vtable_id).get_type_name()
    child_vtable = utils.get_typeinf(child_vtable_name)
    logging.debug(
        "add_to_struct %s %s", parent_vtable_struct.get_tid(), str(child_vtable)
    )
    if ida_typeinf.tinfo_t(tid=child_vtable_id).get_size() == 0:
        utils.add_to_struct(
            ida_typeinf.tinfo_t(tid=child_vtable_id), "dummy", None
        )
    index, new_member = utils.add_to_struct(
        parent_vtable_struct, get_class_vtables_field_name(child_name), child_vtable
    )
    ida_xref.add_dref(
        new_member.type.get_tid(), child_vtable_id, ida_xref.XREF_USER | ida_xref.dr_O
    )


def update_func_name_with_class(func_ea, class_name):
    name = ida_name.get_ea_name(func_ea)
    if name.startswith("sub_"):
        new_name = class_name + VTABLE_DELIMITER + name
        return utils.set_func_name(func_ea, new_name), True
    return name, False


def update_func_this(func_ea, this_type=None):
    functype = None
    try:
        func_details = utils.get_func_details(func_ea)
        logging.info(f"{func_details=}")
        if func_details is None:
            return None
        if this_type:
            if len(func_details) > 0:
                func_details[0].name = "this"
                func_details[0].type = this_type
        functype = utils.update_func_details(func_ea, func_details)
        logging.info(f"{functype=}")
    except ida_hexrays.DecompilationFailure as e:
        logging.exception("Couldn't decompile 0x%x", func_ea)
    return functype


def add_class_vtable(struct_ptr, vtable_name, offset=BADADDR, vtable_field_name=None):
    if vtable_field_name is None:
        class_name = struct_ptr.get_type_name()
        vtable_field_name = get_class_vtable_field_name(class_name)
    vtable_id = ida_typeinf.tinfo_t(name=vtable_name).get_tid()
    vtable_type_ptr = utils.get_typeinf_ptr(vtable_name)
    _, new_member = utils.add_to_struct(
        struct_ptr, vtable_field_name, vtable_type_ptr, offset, overwrite=True
    )
    if new_member is None:
        logging.warning(
            "vtable of %s couldn't added at offset %d", str(vtable_type_ptr), offset
        )
    else:
        ida_xref.add_dref(new_member.type.get_tid(), vtable_id, ida_xref.XREF_USER | ida_xref.dr_O)


@batchmode
def post_func_name_change(new_name, ea):
    xrefs = idautils.XrefsTo(ea, ida_xref.XREF_USER)
    xrefs = filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs)
    args_list = []
    for xref in xrefs:
        member = ida_typeinf.udm_t()
        ida_typeinf.tinfo_t().get_udm_by_tid(member, xref.frm)
        struct = ida_typeinf.tinfo_t(tid=xref.frm)
        if member is not None and struct is not None:
            args_list.append([struct, member.offset(), new_name])

    return utils.set_member_name, args_list


def post_struct_member_name_change(member, new_name):
    xrefs = idautils.XrefsFrom(member.type.get_tid())
    xrefs = filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs)
    for xref in xrefs:
        if utils.is_func(xref.to):
            utils.set_func_name(xref.to, new_name)


def post_struct_member_type_change(member):
    xrefs = idautils.XrefsFrom(member.type.get_tid())
    xrefs = filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs)
    for xref in xrefs:
        if utils.is_func(xref.to):
            function_ptr_tinfo = utils.get_member_tinfo(member)
            if function_ptr_tinfo.is_funcptr():
                function_tinfo = function_ptr_tinfo.get_pointed_object()
                if function_tinfo is not None:
                    ida_typeinf.apply_tinfo(
                        xref.to, function_tinfo, ida_typeinf.TINFO_DEFINITE
                    )


@batchmode
def post_func_type_change(pfn):
    ea = pfn.start_ea
    xrefs = idautils.XrefsTo(ea, ida_xref.XREF_USER)
    xrefs = list(filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs))
    args_list = []
    if len(xrefs) == 0:
        return None, []
    try:
        xfunc = ida_hexrays.decompile(ea)
        func_ptr_typeinf = utils.get_typeinf_ptr(xfunc.type)
        for xref in xrefs:
            member = ida_typeinf.udm_t()
            ida_typeinf.tinfo_t().get_udm_by_tid(member, xref.frm)
            struct = ida_typeinf.tinfo_t(tid=xref.frm)
            index, _ = struct.get_udm(0)
            if member is not None and struct is not None:
                args_list.append(
                    [struct, index, func_ptr_typeinf, ida_typeinf.TINFO_DEFINITE]
                )
    except Exception:
        pass
    return ida_typeinf.tinfo_t.set_udm_type, args_list


def make_funcptr_pt(func, this_type):
    return utils.get_typeinf(f"void (*)({str(this_type)} *)")


def update_vtable_struct(
    functions_ea,
    vtable_struct,
    class_name,
    this_type=None,
    get_next_func_callback=get_vtable_line,
    vtable_head=None,
    ignore_list=None,
    add_dummy_member=False,
    pure_virtual_name=None,
    parent_name=None,
    add_func_this=True,
):
    is_first_member = True
    if this_type is None:
        this_type = utils.get_typeinf_ptr(class_name)
    if not add_func_this:
        this_type = None
    func, next_func = get_next_func_callback(
        functions_ea, ignore_list=ignore_list, pure_virtual_name=pure_virtual_name
    )
    dummy_i = 1
    function_count = 0
    while func is not None:
        new_func_name, is_name_changed = update_func_name_with_class(func, class_name)
        func_ptr = None
        if ida_hexrays.init_hexrays_plugin():
            if is_name_changed:
                func_type = update_func_this(func, this_type)
            else:
                func_type = update_func_this(func, None)
            if func_type is not None:
                func_ptr = utils.get_typeinf_ptr(func_type)
        else:
            func_ptr = make_funcptr_pt(func, this_type)
        if add_dummy_member:
            utils.add_to_struct(vtable_struct, f"dummy_{dummy_i}", func_ptr)
            dummy_i += 1
        if not func_ptr:
            func_ptr = ida_typeinf.tinfo_t("void (*)(void)")
        if function_count == 0:
            # We did an hack for vtables contained in union vtable with one dummy member
            _, ptr_member = utils.add_to_struct(
                vtable_struct, new_func_name, func_ptr, 0, overwrite=True
            )
        else:
            _, ptr_member = utils.add_to_struct(
                vtable_struct,
                new_func_name,
                func_ptr,
                function_count * utils.WORD_LEN * utils.BYTE_SIZE,
                is_offset=True
            )
        if ptr_member is None:
            logging.exception(
                "Couldn't add %s(%s) to %d",
                new_func_name,
                str(func_ptr),
                vtable_struct.get_tid(),
            )
        ida_xref.add_dref(ptr_member.type.get_tid(), func, ida_xref.XREF_USER | ida_xref.dr_I)
        func, next_func = get_next_func_callback(
            next_func, ignore_list=ignore_list, pure_virtual_name=pure_virtual_name
        )
        function_count += 1

    vtable_size = vtable_struct.get_size()

    if vtable_head is None:
        vtable_head = functions_ea
    ida_bytes.del_items(vtable_head, ida_bytes.DELIT_SIMPLE, vtable_size)
    ida_bytes.create_struct(vtable_head, vtable_size, vtable_struct.get_tid())
    if parent_name is None and this_type:
        parent = utils.deref_struct_from_tinfo(this_type)
        parent_name = parent.get_type_name()
        if parent_name == class_name:
            parent_name = None
    utils.set_name_retry(vtable_head, get_vtable_instance_name(class_name, parent_name))


def is_valid_func_char(c):
    ALLOWED_CHARS = [":", "_"]
    return c.isalnum() or c in ALLOWED_CHARS


def find_valid_cppname_in_line(line, idx):
    end_idx = idx
    start_idx = idx
    if len(line) < idx:
        return None
    while start_idx >= 0 and is_valid_func_char(line[start_idx]):
        if line[start_idx] == ":":
            if line[start_idx - 1] == ":":
                start_idx -= 1
            else:
                break
        start_idx -= 1
    while end_idx < len(line) and is_valid_func_char(line[end_idx]):
        if line[end_idx] == ":":
            if line[end_idx + 1] == ":":
                end_idx += 1
            else:
                break
        end_idx += 1
    if end_idx > start_idx:
        return line[start_idx + 1 : end_idx]
    return None


def get_overriden_func_names(union_name, offset, get_not_funcs_members=False):
    sptr = utils.get_sptr_by_name(union_name)
    res = []
    if not sptr.is_union():
        return res

    for i in range(sptr.get_size()):
        idx, member = sptr.get_udm_by_offset(i)
        if member is None: # Added check for None
            continue
        cls = member.name
        tinfo = utils.get_member_tinfo(member)
        logging.debug("Trying %s", cls)
        if cls == get_interface_empty_vtable_name() or not tinfo.is_ptr():
            continue
        pointed_obj = tinfo.get_pointed_object()
        if not pointed_obj.is_struct():
            continue
        vtable_sptr = utils.get_sptr_by_name(pointed_obj.get_final_type_name())
        if vtable_sptr.get_size() <= offset:
            continue
        idx, funcptr_member = vtable_sptr.get_udm_by_offset(offset)
        if funcptr_member is None: # Added check for None
            continue
        funcptr_type = utils.get_member_tinfo(funcptr_member)
        func_name = funcptr_member.name
        if not funcptr_type.is_funcptr() and not get_not_funcs_members:
            continue
        res.append((cls, func_name))
    return res


def set_polymorhpic_func_name(union_name, offset, name, force=False):
    for _, func_name in get_overriden_func_names(union_name, offset):
        func_name_splitted = func_name.split(VTABLE_DELIMITER)
        local_func_name = func_name_splitted[-1]
        if local_func_name != name and (force or local_func_name.startswith("sub_")):
            ea = utils.get_func_ea_by_name(func_name)
            if ea != BADADDR:
                new_func_name = VTABLE_DELIMITER.join(func_name_splitted[:-1])
                if new_func_name != "":
                    new_func_name += VTABLE_DELIMITER
                new_func_name += name
                logging.debug("0x%x -> %s", ea, new_func_name)
                utils.set_func_name(ea, new_func_name)


def create_class(class_name, has_vtable, parent_class=None):
    udt = ida_typeinf.udt_type_data_t()
    type_info = ida_typeinf.tinfo_t()
    udt.is_union = False
    if (
        type_info.create_udt(udt) and
        type_info.set_named_type(None, class_name) == ida_typeinf.TERR_OK
    ):
        return type_info
    return None


def create_vtable_struct(sptr, name, vtable_offset, parent_name=None):
    logging.debug("create_vtable_struct(%s, %d)", name, vtable_offset)
    vtable_details = find_vtable_at_offset(sptr, vtable_offset)
    parent_vtable_member = None
    parent_vtable_struct = None
    parent_name = None
    parents_chain = None
    if vtable_details is not None:
        logging.debug("Found parent vtable %s %d", name, vtable_offset)
        parent_vtable_member, parent_vtable_struct, parents_chain = vtable_details
    else:
        logging.debug("Couldn't found parent vtable %s %d", name, vtable_offset)
    if parent_vtable_member is not None:
        parent_name = parent_vtable_struct.get_type_name()
    vtable_name = get_class_vtable_struct_name(name, vtable_offset)
    if vtable_offset == 0:
        this_type = utils.get_typeinf_ptr(name)
    else:
        this_type = utils.get_typeinf_ptr(parent_name)
    if vtable_name is None:
        logging.exception(
            "create_vtable_struct(%s, %d): vtable_name is" " None", name, vtable_offset
        )
    udt = ida_typeinf.udt_type_data_t()
    vtable_struct = utils.get_or_create_struct(vtable_name)
    if vtable_struct.get_tid() == BADADDR:
        logging.exception("Couldn't create struct %s", vtable_name)
    if parents_chain:
        for parent_name, offset in parents_chain:
            add_child_vtable(parent_name, name, vtable_struct.get_tid(), offset * utils.BYTE_SIZE)
    else:
        add_class_vtable(sptr, vtable_name, vtable_offset)

    return vtable_struct, this_type


def make_vtable(
        class_name,
        vtable_ea=None,
        vtable_ea_stop=None,
        offset_in_class=0,
        parent_name=None,
        add_func_this=True,
        _get_vtable_line=get_vtable_line,
):
    if not vtable_ea and not vtable_ea_stop:
        vtable_ea, vtable_ea_stop = utils.get_selected_range_or_line()
    vtable_struct, this_type = create_vtable_struct(
        utils.get_or_create_struct(class_name), class_name, offset_in_class * utils.BYTE_SIZE,
        parent_name=parent_name
    )
    logging.info(f"{vtable_ea=}, {vtable_ea_stop=}, ")
    update_vtable_struct(
        vtable_ea,
        vtable_struct,
        class_name,
        this_type=this_type,
        get_next_func_callback=partial(_get_vtable_line, stop_ea=vtable_ea_stop),
        parent_name=parent_name,
        add_func_this=add_func_this,
    )


def add_baseclass(class_name, baseclass_name, baseclass_offset=0, to_refresh=False):
    member_name = get_base_member_name(baseclass_name, baseclass_offset)
    struct_ptr = utils.get_sptr_by_name(class_name)
    baseclass_ptr = utils.get_sptr_by_name(baseclass_name)
    if not struct_ptr or not baseclass_ptr:
        return False
    _, member = utils.add_to_struct(struct_ptr, member_name,
                                 member_type=utils.get_typeinf(baseclass_name),
                                 offset=baseclass_offset,
                                 overwrite=True)
    if not member:
        logging.debug(f"add_baseclass({class_name}. {baseclass_name}): member not found")
        return False
    if to_refresh:
        utils.refresh_struct(struct_ptr)
    return True
