#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import sys
import traceback
import colorama
import pathlib
import pn532_utils
import pn532_cli_unit
import prompt_toolkit
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from pn532_utils import CR, CG, CY, C0, CM
import pn532_com

BANNER_PN532Killer = """
██████╗ ███╗   ██╗███████╗██████╗ ██████╗ ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝╚════██╗╚════██╗██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
██████╔╝██╔██╗ ██║███████╗ █████╔╝ █████╔╝█████╔╝ ██║██║     ██║     █████╗  ██████╔╝
██╔═══╝ ██║╚██╗██║╚════██║ ╚═══██╗██╔═══╝ ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
██║     ██║ ╚████║███████║██████╔╝███████╗██║  ██╗██║███████╗███████╗███████╗██║  ██║
╚═╝     ╚═╝  ╚═══╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
"""
# https://patorjk.com/software/taag/#p=display&f=ANSI%20Shadow&t=PN532%20CLI
BANNER = """
██████╗ ███╗   ██╗███████╗██████╗ ██████╗      ██████╗██╗     ██╗
██╔══██╗████╗  ██║██╔════╝╚════██╗╚════██╗    ██╔════╝██║     ██║
██████╔╝██╔██╗ ██║███████╗ █████╔╝ █████╔╝    ██║     ██║     ██║
██╔═══╝ ██║╚██╗██║╚════██║ ╚═══██╗██╔═══╝     ██║     ██║     ██║
██║     ██║ ╚████║███████║██████╔╝███████╗    ╚██████╗███████╗██║
╚═╝     ╚═╝  ╚═══╝╚══════╝╚═════╝ ╚══════╝     ╚═════╝╚══════╝╚═╝
"""

class Pn532CLI:
    def __init__(self):
        self.device_com = pn532_com.Pn532Com()
        parser = argparse.ArgumentParser()
        parser.add_argument('--debug', action='store_true', help='Enable debug mode')
        args = parser.parse_args()
        if args.debug:
            pn532_com.DEBUG = True

    def get_cmd_node(self, node: pn532_utils.CLITree,
                     cmdline: list[str]) -> tuple[pn532_utils.CLITree, list[str]]:
        """
        Recursively traverse the command line tree to get to the matching node

        :return: last matching CLITree node, remaining tokens
        """
        # No more subcommands to parse, return node
        if cmdline == []:
            return node, []

        for child in node.children:
            if cmdline[0] == child.name:
                return self.get_cmd_node(child, cmdline[1:])

        # No matching child node
        return node, cmdline[:]

    def exec_cmd(self, cmd_str):
        if cmd_str == '':
            return
        if cmd_str in ["quit", "q", "e"]:
            cmd_str = 'exit'

        # parse cmd
        argv = cmd_str.split()

        tree_node, arg_list = self.get_cmd_node(pn532_cli_unit.root, argv)
        if not tree_node.cls:
            # Found tree node is a group without an implementation, print children
            print("".ljust(18, "-") + "".ljust(10) + "".ljust(30, "-"))
            for child in tree_node.children:
                cmd_title = f"{CG}{child.name}{C0}"
                if not child.cls:
                    help_line = (f" - {cmd_title}".ljust(37)) + f"{{ {child.help_text}... }}"
                else:
                    help_line = (f" - {cmd_title}".ljust(37)) + f"{child.help_text}"
                print(help_line)
            return

        unit: pn532_cli_unit.BaseCLIUnit = tree_node.cls()
        unit.device_com = self.device_com
        args_parse_result = unit.args_parser()

        assert args_parse_result is not None
        args: argparse.ArgumentParser = args_parse_result
        args.prog = tree_node.fullname
        try:
            args_parse_result = args.parse_args(arg_list)
            if args.help_requested:
                return
        except pn532_utils.ArgsParserError as e:
            args.print_help()
            print(f'{CY}'+str(e).strip()+f'{C0}', end="\n\n")
            return
        except pn532_utils.ParserExitIntercept:
            # don't exit process.
            return
        try:
            # before process cmd, we need to do something...
            if not unit.before_exec(args_parse_result):
                return

            # start process cmd, delay error to call after_exec firstly
            error = None
            try:
                unit.on_exec(args_parse_result)
            except Exception as e:
                error = e
            unit.after_exec(args_parse_result)
            if error is not None:
                raise error

        except (pn532_utils.UnexpectedResponseError, pn532_utils.ArgsParserError) as e:
            print(f"{CR}{str(e)}{C0}")
        except Exception:
            print(
                f"CLI exception: {CR}{traceback.format_exc()}{C0}")

    def set_device_name(self, device_name):
        self.device_com.set_device_name(device_name)

    def get_prompt(self):
        # Retrieve the cli prompt
        # :return: current cmd prompt
        if self.device_com.isOpen():
            # 判断连接类型
            port = getattr(self.device_com, 'port_string', None)
            conn_type = "USB"
            if port:
                if isinstance(port, str):
                    if port.startswith('tcp:'):
                        conn_type = "TCP"
                    elif port.startswith('udp:'):
                        conn_type = "UDP"
            # 兼容 CommunicationFactory 连接
            if hasattr(self.device_com, 'communication'):
                comm = self.device_com.communication
                if comm.__class__.__name__ == "TCPCommunication":
                    conn_type = "TCP"
                elif comm.__class__.__name__ == "UDPCommunication":
                    conn_type = "UDP"
            device_string = f"{CG}{conn_type}"
        else:
            device_string = f"{CR}Offline"
        device_name = self.device_com.get_device_name()
        status = f"[{device_string}{C0}] {device_name} --> "
        return status

    @staticmethod
    def print_banner():
        """
            print chameleon ascii banner.

        :return:
        """
        print(f"{CM}{BANNER}{C0}")
        print(f"{CM}  A Python-based CLI for PN532 / PN532Killer{C0}")
        print(f"{CM}=============================================={C0}")

    def startCLI(self):
        self.completer = pn532_utils.CustomNestedCompleter.from_clitree(pn532_cli_unit.root)
        self.session = prompt_toolkit.PromptSession(completer=self.completer,
                                                    history=FileHistory(str(pathlib.Path.home() /
                                                                            ".pn532_history")))

        if not pn532_com.DEBUG:
            self.print_banner()
        cmd_strs = []
        cmd_str = ''
        while True:
            # Check connection status before prompting
            if self.device_com.isOpen():
                # Double check if communication is still valid
                if hasattr(self.device_com, 'communication') and self.device_com.communication:
                    if not self.device_com.communication.is_open():
                        print(f"{colorama.Fore.RED}Connection lost! Device disconnected.{colorama.Style.RESET_ALL}")
                        self.device_com.close()
            
            if cmd_strs:
                print(f"{colorama.Fore.GREEN}>>> {cmd_strs[-1]}{colorama.Style.RESET_ALL}")
            # cmd_str = cmd_strs.pop(0)
            else:
                try:
                    cmd_str = self.session.prompt(
                        ANSI(self.get_prompt())).strip()
                    cmd_strs = cmd_str.replace(
                        "\r\n", "\n").replace("\r", "\n").split("\n")
                    cmd_str = cmd_strs.pop(0)
                except EOFError:
                    cmd_str = 'exit'
                except KeyboardInterrupt:
                    cmd_str = 'exit'
            self.exec_cmd(cmd_str)


if __name__ == '__main__':
    if sys.version_info < (3, 9):
        raise Exception("This script requires at least Python 3.9")
    colorama.init(autoreset=True)
    Pn532CLI().startCLI()
