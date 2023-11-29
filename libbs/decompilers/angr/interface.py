import logging
import os
from typing import Optional, Dict, List
from pathlib import Path

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator

from libbs.api.decompiler_interface import (
    DecompilerInterface,
)
from libbs.data import (
    Function, FunctionHeader, Comment, StackVariable, FunctionArgument, Artifact
)
from .artifact_lifter import AngrArtifactLifter

l = logging.getLogger(__name__)

try:
    from angrmanagement.ui.views import CodeView
except ImportError:
    l.debug("angr-management module not found... likely running headless.")

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


class AngrInterface(DecompilerInterface):
    """
    The class used for all pushing/pulling and merging based actions with BinSync data.
    This class is responsible for handling callbacks that are done by changes from the local user
    and responsible for running a thread to get new changes from other users.
    """

    def __init__(self, workspace=None, headless=False, binary_path: Path = None, **kwargs):
        self.workspace = workspace
        if workspace is None and not headless:
            l.critical("The workspace provided is None, which will result in a broken BinSync.")
            return

        self.main_instance = workspace.main_instance if workspace else self
        self._binary_path = Path(binary_path) if binary_path is not None else binary_path
        super().__init__(name="angr", artifact_lifter=AngrArtifactLifter(self), headless=headless, **kwargs)

    def _init_headless_components(self):
        if self._binary_path is None or not self._binary_path.exists():
            return

        self.project = angr.Project(str(self._binary_path), auto_load_libs=False)
        cfg = self.project.analyses.CFG(show_progressbar=True, normalize=True, data_references=True)
        self.project.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

    def binary_hash(self) -> str:
        return self.main_instance.project.loader.main_object.md5.hex()

    def active_context(self):
        curr_view = self.workspace.view_manager.current_tab
        if not curr_view:
            return None

        try:
            func = curr_view.function
        except NotImplementedError:
            return None

        if func is None or func.am_obj is None:
            return None

        func_addr = self.rebase_addr(func.addr)

        return Function(
            func_addr, 0, header=FunctionHeader(func.name, func_addr)
        )

    def binary_path(self) -> Optional[str]:
        try:
            return self.main_instance.project.loader.main_object.binary
        # pylint: disable=broad-except
        except Exception:
            return None

    def get_func_size(self, func_addr) -> int:
        try:
            func = self.main_instance.project.kb.functions[func_addr]
            return func.size
        except KeyError:
            return 0

    def rebase_addr(self, addr, up=False):
        is_pie = self.main_instance.project.loader.main_object.pic
        if not is_pie:
            return addr

        base_addr = self.main_instance.project.loader.main_object.mapped_base
        rebased_addr = addr
        if up and addr < base_addr:
            rebased_addr = addr + base_addr
        elif not up and addr > base_addr:
            rebased_addr = addr - base_addr

        return rebased_addr

    def goto_address(self, func_addr):
        self.workspace.jump_to(self.rebase_addr(func_addr, up=True))

    def xrefs_to(self, artifact: Artifact) -> List[Artifact]:
        if not isinstance(artifact, Function):
            l.warning("xrefs_to is only implemented for functions.")
            return []

        function: Function = self.lower_artifact(artifact)
        program_cfg = self.main_instance.kb.cfgs.get_most_accurate()
        if program_cfg is None:
            return []

        func_node = program_cfg.get_any_node(function.addr)
        if func_node is None:
            return []

        xrefs = []
        for node in program_cfg.graph.predecessors(func_node):
            func_addr = node.function_address
            if func_addr is None:
                continue

            xrefs.append(Function(func_addr, 0))

        return xrefs

    def _decompile(self, function: Function) -> Optional[str]:
        func = self.main_instance.project.kb.functions.get(function.addr, None)
        if func is None:
            return None

        try:
            codegen = self.decompile_function(func)
        except Exception as e:
            l.warning(f"Failed to decompile {func} because {e}")
            codegen = None

        if not codegen or not codegen.text:
            return None

        return codegen.text

    #
    # Artifact API
    #

    def _set_function(self, func: Function, **kwargs) -> bool:
        angr_func = self.main_instance.project.kb.functions[func.addr]

        # re-decompile a function if needed
        decompilation = self.decompile_function(angr_func)
        changes = super()._set_function(func, decompilation=decompilation, **kwargs)
        if not self.headless:
            self.refresh_decompilation(func.addr)

        return changes

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        try:
            _func = self.main_instance.project.kb.functions[addr]
        except KeyError:
            return None

        func = Function(_func.addr, _func.size)
        type_ = _func.prototype.returnty.c_repr() if _func.prototype.returnty else None
        func.header = FunctionHeader(
            _func.name, _func.addr, type_=type_
        )

        try:
            decompilation = self.decompile_function(_func)
        except Exception as e:
            l.warning(f"Failed to decompile function {hex(_func.addr)}: {e}")
            decompilation = None

        if not decompilation:
            return func

        func.header.args = self.func_args_as_libbs_args(decompilation)
        # overwrite type again since it can change with decompilation
        if decompilation.cfunc.functy.returnty:
            func.header.type = decompilation.cfunc.functy.returnty.c_repr()

        stack_vars = {
            angr_sv.offset: StackVariable(
                angr_sv.offset, angr_sv.name, self.stack_var_type_str(decompilation, angr_sv), angr_sv.size, func.addr
            )
            for angr_sv in self.stack_vars_in_dec(decompilation)
        }
        func.stack_vars = stack_vars

        return func

    def _functions(self) -> Dict[int, Function]:
        funcs = {}
        for addr, func in self.main_instance.project.kb.functions.items():
            funcs[addr] = Function(addr, func.size)
            funcs[addr].name = func.name

        return funcs

    def _set_function_header(self, fheader: FunctionHeader, decompilation=None, **kwargs) -> bool:
        angr_func = self.main_instance.project.kb.functions[fheader.addr]
        changes = False
        if not fheader:
            return changes

        if fheader.name and fheader.name != angr_func.name:
            angr_func.name = fheader.name
            decompilation.cfunc.name = fheader.name
            decompilation.cfunc.demangled_name = fheader.name
            changes = True

        if fheader.args:
            for i, arg in fheader.args.items():
                if i >= len(decompilation.cfunc.arg_list):
                    break
                if decompilation.cfunc.arg_list[i].variable.name != arg.name:
                    decompilation.cfunc.arg_list[i].variable.name = arg.name
                    changes = True

        return changes

    def _set_stack_variable(self, svar: StackVariable, decompilation=None, **kwargs) -> bool:
        changed = False
        code_var = AngrInterface.find_stack_var_in_codegen(decompilation, svar.offset)
        if code_var:
            code_var.name = svar.name
            code_var.renamed = True
            changed = True

        return changed

    def _set_comment(self, comment: Comment, decompilation=None, **kwargs) -> bool:
        changed = False
        if comment.decompiled and comment.addr != comment.func_addr:
            try:
                pos = decompilation.map_addr_to_pos.get_nearest_pos(comment.addr)
                corrected_addr = decompilation.map_pos_to_addr.get_node(pos).tags['ins_addr']
            # pylint: disable=broad-except
            except Exception:
                return changed

            dec_cmt = decompilation.stmt_comments.get(corrected_addr, None)
            if dec_cmt != comment.comment:
                decompilation.stmt_comments[corrected_addr] = comment.comment
                changed |= True
        else:
            kb_cmt = self.main_instance.project.kb.comments.get(comment.addr, None)
            if kb_cmt != comment.comment:
                self.main_instance.project.kb.comments[comment.addr] = comment.comment
                changed |= True

        return changed

    #
    #   Utils
    #

    def refresh_decompilation(self, func_addr):
        self.main_instance.workspace.jump_to(func_addr)
        view = self.main_instance.workspace._get_or_create_view("pseudocode", CodeView)
        view.codegen.am_event()
        view.focus()

    def _headless_decompile(self, func):
        cfg = self.project.kb.cfgs.get_most_accurate()
        self.project.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        options = [([
            o for o in angr.analyses.decompiler.decompilation_options.options
            if o.param == "structurer_cls"
        ][0], "phoenix")]

        self.main_instance.project.analyses.Decompiler(
            func, flavor='pseudocode', options=options, optimization_passes=all_optimization_passes
        )

    def _angr_management_decompile(self, func):
        # recover direct pseudocode
        self.main_instance.project.analyses.Decompiler(func, flavor='pseudocode')

        # attempt to get source code if its available
        source_root = None
        if self.main_instance.original_binary_path:
            source_root = os.path.dirname(self.main_instance.original_binary_path)
        self.main_instance.project.analyses.ImportSourceCode(func, flavor='source', source_root=source_root)

    def decompile_function(self, func, refresh_gui=False):
        # check for known decompilation
        available = self.main_instance.project.kb.structured_code.available_flavors(func.addr)
        should_decompile = False
        if 'pseudocode' not in available:
            should_decompile = True
        else:
            cached = self.main_instance.project.kb.structured_code[(func.addr, 'pseudocode')]
            if isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = True

        if should_decompile:
            if not self.headless:
                self._angr_management_decompile(func)
            else:
                self._headless_decompile(func)

        # grab newly cached pseudocode
        decomp = self.main_instance.project.kb.structured_code[(func.addr, 'pseudocode')].codegen

        # refresh the UI after decompiling
        if refresh_gui and not self.headless:
            self.workspace.reload()

            # re-decompile current view to cause a refresh
            current_tab = self.workspace.view_manager.current_tab
            if isinstance(current_tab, CodeView) and current_tab.function == func:
                self.workspace.decompile_current_function()

        return decomp

    #
    # Function Data Helpers
    #

    @staticmethod
    def find_stack_var_in_codegen(decompilation, stack_offset: int) -> Optional[angr.sim_variable.SimStackVariable]:
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset") and var.offset == stack_offset:
                return var

        return None

    @staticmethod
    def stack_var_type_str(decompilation, stack_var: angr.sim_variable.SimStackVariable):
        try:
            var_type = decompilation.cfunc.variable_manager.get_variable_type(stack_var)
        # pylint: disable=broad-except
        except Exception:
            return None

        return var_type.c_repr() if var_type is not None else None

    @staticmethod
    def stack_vars_in_dec(decompilation):
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset"):
                yield var

    @staticmethod
    def func_args_as_libbs_args(decompilation) -> Dict[int, FunctionArgument]:
        args = {}
        if not decompilation.cfunc.arg_list:
            return args
        
        for idx, arg in enumerate(decompilation.cfunc.arg_list):
            type_ = arg.variable_type.c_repr() if arg.variable_type is not None else None
            args[idx] = FunctionArgument(
                idx, arg.variable.name, type_, arg.variable.size
            )

        return args

    @staticmethod
    def func_insn_addrs(func: angr.knowledge_plugins.Function):
        insn_addrs = set()
        for block in func.blocks:
            insn_addrs.update(block.instruction_addrs)

        return insn_addrs

    def get_closest_function(self, addr):
        try:
            func_addr = self.workspace.main_instance.project.kb.cfgs.get_most_accurate()\
                .get_any_node(addr, anyaddr=True)\
                .function_address
        except AttributeError:
            func_addr = None

        return func_addr

