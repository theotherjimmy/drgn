# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Bugs
-------

The ``drgn.helpers.linux.bug`` module contains helpers for displaying
information about bugs & warnings recorded by the BUG() & WARN() macros.
"""
from typing import Optional

from drgn import Object, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.kconfig import get_kconfig

__all__ = (
    "global_bug_table",
    "bug_addr",
    "bug_file",
    "bug_format",
    "bug_line",
    "bug_flags",
    "bug_is_warning",
    "bug_is_once",
    "bug_is_done",
    "bug_is_no_cut_here",
    "bug_get_taint",
    "print_bug",
    "print_triggered_warnings",
    "print_module_bugs",
    "module_bugs_table",
)


def _check_for_bug_support(prog: Program) -> None:
    # raise a NotImplementedError when bug support is disabled
    if get_kconfig()["CONFIG_BUG"] == "n":
        raise NotImplementedError("Bug recording disabled in kconfig (CONFIG_BUG=n)")


@takes_program_or_default
def global_bug_table(prog: Program) -> Object:
    """
    Returns all loaded kernel modules

    :returns: Iterable of ``struct module *`` objects
    """
    _check_for_bug_support(prog)
    bug_entry_struct = prog.type("struct bug_entry")
    bug_table_start = prog.symbol("__start___bug_table").address
    bug_table_stop = prog.symbol("__stop___bug_table").address
    if not bug_table_start or not bug_table_stop or not bug_entry_struct.size:
        raise NotImplementedError("bug table missing")
    bug_table_size = int((bug_table_stop - bug_table_start) / bug_entry_struct.size)
    table_type = prog.array_type(bug_entry_struct, bug_table_size)
    return Object(prog, table_type, address=bug_table_start)


def _bug_attr(bug: Object, attr: str, type: str) -> Object:
    # Get a bug attribute, which may be
    if get_kconfig(bug.prog_)["CONFIG_GENERIC_BUG_RELATIVE_POINTERS"] == "y":
        disp = bug.member_(f"{attr}_disp")
        addr = disp.address_ + disp.value_()
    else:
        addr = bug.member_(attr)
    return Object(bug.prog_, type, addr)


def bug_addr(bug: Object) -> Object:
    """
    Returns the address of the instruction that logged the bug

    :returns: the address as an ``unsigned long`` object
    """
    return _bug_attr(bug, "bug_addr", "unsigned long")


def bug_file(bug: Object) -> Object:
    """
    Returns the file name of the logged bug

    :returns: the file name as a ``char *`` object
    """
    return _bug_attr(bug, "file", "char *")


def bug_format(bug: Object) -> Object:
    """
    Returns the format string of the logged bug

    :returns: the format string as a ``char *`` object
    """
    return _bug_attr(bug, "format", "char *")


def bug_line(bug: Object) -> Object:
    """
    Returns the line number of the logged bug

    :returns: the line number as a ``unsigned short`` object
    """
    return bug.member_("line")


def bug_flags(bug: Object) -> Object:
    """
    Returns the flags (WARN, ONCE, etc.) of the logged bug

    :returns: the flags as a ``unsigned short`` object
    """
    return bug.member_("flags")


def bug_is_warning(bug: Object) -> bool:
    """
    Return a boolean indicating that a bug is a warning.
    """
    return bug.flags & 0b1 == 0b1


def bug_is_once(bug: Object) -> bool:
    """
    Return a boolean indicating that a bug is silenced after being triggered once.
    """
    return bug.flags & 0b10 == 0b10


def bug_is_done(bug: Object) -> bool:
    """
    Return a boolean indicating that a bug has already emitted a warning.
    """
    return bug.flags & 0b100 == 0b100


def bug_is_no_cut_here(bug: Object) -> bool:
    """
    Return a boolean indicating that a bug should not emit a cut here marker in dmesg.
    """
    return bug.flags & 0b1 == 0b1


def bug_get_taint(bug: Object) -> int:
    """
    Return a bugs taint flag.
    """
    return int(bug.flags >> 8)


def _format_bug_flags(bug: Object) -> str:
    flags = []
    if bug_is_warning(bug):
        flags.append("WARN")
    if bug_is_once(bug):
        flags.append("ONCE")
    if bug_is_done(bug):
        flags.append("DONE")
    if bug_is_no_cut_here(bug):
        flags.append("NO-CUT")
    taint = bug_get_taint(bug)
    if taint != 0:
        flags.append(f"Taint={taint}")
    return " ".join(flags)


def _symbolize(prog: Program, addr: int, offset_base: int) -> Optional[str]:
    try:
        sym = prog.symbol(addr)
    except LookupError:
        return ""
    sym_offset = addr - sym.address
    if sym_offset == 0:
        return f"\t<{sym.name}>"
    num_string = f"0x{sym_offset:x}" if offset_base == 16 else f"{sym_offset:d}"
    return f"\t<{sym.name}+{num_string}>"


def print_bug(bug: Object, offset_base: int = 10) -> None:
    """
    Print the details of a bug.
    """
    has_file_line = get_kconfig(bug.prog_)["CONFIG_DEBUG_BUGVERBOSE"] == "y"
    symbol = _symbolize(bug.prog_, bug_addr(bug).value_(), offset_base)
    flags = _format_bug_flags(bug)
    try:
        if has_file_line:
            print(
                f"{bug_file(bug).string_().decode()}:{bug_line(bug).value_()}@0x{bug_addr(bug).value_():x}{symbol}: {bug_format(bug).string_().decode()} {flags}"
            )
        else:
            print(
                f"0x{bug_addr(bug).value_():x}{symbol}: {bug_format(bug).string_().decode()} {flags}"
            )
    except LookupError:
        if has_file_line:
            print(
                f"{bug_file(bug).string_().decode()}:{bug_line(bug).value_()}@0x{bug_addr(bug).value_():x}{symbol} {flags}"
            )
        else:
            print(f"@0x{bug_addr(bug).value_():x}{symbol} {flags}")


@takes_program_or_default
def print_triggered_warnings(prog: Program) -> None:
    """
    Print every bug emitted by the linux kernel.
    """
    for bug in global_bug_table(prog):
        if (bug_flags(bug).value_() & 0b100) == 0b100:
            print_bug(bug)


def module_bugs_table(mod: Object) -> Object:
    table_type = mod.prog_.array_type(mod.bug_table[0].type_, mod.num_bugs.value_())
    return Object(mod.prog_, table_type, address=mod.bug_table)


def print_module_bugs(mod: Object) -> None:
    """
    Print every bug emitted by the specified module linux kernel.
    """
    for bug in module_bugs_table(mod):
        print_bug(bug)
