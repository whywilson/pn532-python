import argparse
import colorama
import ndef
from functools import wraps
from typing import Union, Callable, Any, Optional
from prompt_toolkit.completion import Completer, NestedCompleter, WordCompleter
from prompt_toolkit.completion.base import Completion
from prompt_toolkit.document import Document

from pn532_enum import Status

# Colorama shorthands
CR = colorama.Fore.RED
CG = colorama.Fore.GREEN
CB = colorama.Fore.BLUE
CC = colorama.Fore.CYAN
CY = colorama.Fore.YELLOW
CM = colorama.Fore.MAGENTA
C0 = colorama.Style.RESET_ALL


class ArgsParserError(Exception):
    pass


class ParserExitIntercept(Exception):
    pass


class UnexpectedResponseError(Exception):
    """
    Unexpected response exception
    """


class ArgumentParserNoExit(argparse.ArgumentParser):
    """
        If arg ArgumentParser parse error, we can't exit process,
        we must raise exception to stop parse
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_help = False
        self.description = "Please enter correct parameters"
        self.help_requested = False

    def exit(self, status: int = 0, message: Union[str, None] = None):
        if message:
            raise ParserExitIntercept(message)

    def error(self, message: str):
        args = {'prog': self.prog, 'message': message}
        raise ArgsParserError('%(prog)s: error: %(message)s\n' % args)

    def print_help(self):
        """
        Colorize argparse help
        """
        print("-" * 80)
        print(f"{CR}{self.prog}{C0}\n")
        lines = self.format_help().splitlines()
        usage = lines[:lines.index('')]
        assert usage[0].startswith('usage:')
        usage[0] = usage[0].replace('usage:', f'{CG}usage:{C0}\n ')
        usage[0] = usage[0].replace(self.prog, f'{CR}{self.prog}{C0}')
        usage = [usage[0]] + [x[4:] for x in usage[1:]] + ['']
        lines = lines[lines.index('')+1:]
        desc = lines[:lines.index('')]
        print(f'{CC}'+'\n'.join(desc)+f'{C0}\n')
        print('\n'.join(usage))
        lines = lines[lines.index('')+1:]
        if '' in lines:
            options = lines[:lines.index('')]
            lines = lines[lines.index('')+1:]
        else:
            options = lines
            lines = []
        if len(options) > 0 and options[0].strip() == 'positional arguments:':
            positional_args = options
            positional_args[0] = positional_args[0].replace('positional arguments:', f'{CG}positional arguments:{C0}')
            if len(positional_args) > 1:
                positional_args.append('')
            print('\n'.join(positional_args))
            if '' in lines:
                options = lines[:lines.index('')]
                lines = lines[lines.index('')+1:]
            else:
                options = lines
                lines = []
        if len(options) > 0:
            # 2 variants depending on Python version(?)
            assert options[0].strip() in ['options:', 'optional arguments:']
            options[0] = options[0].replace('options:', f'{CG}options:{C0}')
            options[0] = options[0].replace('optional arguments:', f'{CG}optional arguments:{C0}')
            if len(options) > 1:
                options.append('')
            print('\n'.join(options))
        if len(lines) > 0:
            lines[0] = f'{CG}{lines[0]}{C0}'
            print('\n'.join(lines))
        print('')
        self.help_requested = True

def print_mem_dump(bindata, blocksize):

    hexadecimal_len = blocksize*3+1
    ascii_len = blocksize+1
    print(f"[=] ----+{hexadecimal_len*'-'}+{ascii_len*'-'}")
    print(f"[=] blk | data{(hexadecimal_len-5)*' '}| ascii")
    print(f"[=] ----+{hexadecimal_len*'-'}+{ascii_len*'-'}")

    blocks = [bindata[i:i+blocksize] for i in range(0, len(bindata), blocksize)]
    blk_index = 1
    for b in blocks:
        hexstr = ' '.join(b.hex()[i:i+2] for i in range(0, len(b.hex()), 2))
        asciistr = ''.join([chr(b[i]) if (b[i] > 31 and b[i] < 127) else '.' for i in range(0,len(b),1)])
        print(f"[=] {blk_index:3} | {hexstr.upper()} | {asciistr} ")
        blk_index += 1

def expect_response(accepted_responses: Union[int, list[int]]) -> Callable[..., Any]:
    """
    Decorator for wrapping a PN532 CMD function to check its response
    for expected return codes and throwing an exception otherwise
    """
    if isinstance(accepted_responses, int):
        accepted_responses = [accepted_responses]

    def decorator(func):
        @wraps(func)
        def error_throwing_func(*args, **kwargs):
            ret = func(*args, **kwargs)
            # print(f"ret: {ret}")
            if ret == None:
                return None
            if ret.status not in accepted_responses:
                try:
                    status_string = str(Status(ret.status))
                except ValueError:
                    status_string = f"Unexpected response and unknown status {ret.status}"
                # raise UnexpectedResponseError(status_string)
            return ret.parsed

        return error_throwing_func

    return decorator


class CLITree:
    """
    Class holding a

    :param name: Name of the command (e.g. "set")
    :param help_text: Hint displayed for the command
    :param fullname: Full name of the command that includes previous commands (e.g. "hw settings animation")
    :param cls: A BaseCLIUnit instance handling the command
    """

    def __init__(self, name: str = "", help_text: Union[str, None] = None, fullname: Union[str, None] = None,
                 children: Union[list["CLITree"], None] = None, cls=None, root=False) -> None:
        self.name = name
        self.help_text = help_text
        self.fullname = fullname if fullname else name
        self.children = children if children else list()
        self.cls = cls
        self.root = root
        if self.help_text is None and not root:
            assert self.cls is not None
            parser = self.cls().args_parser()
            assert parser is not None
            self.help_text = parser.description

    def subgroup(self, name, help_text=None):
        """
        Create a child command group

        :param name: Name of the command group
        :param help_text: Hint displayed for the group
        """
        child = CLITree(
            name=name,
            fullname=f'{self.fullname} {name}' if not self.root else f'{name}',
            help_text=help_text)
        self.children.append(child)
        return child

    def command(self, name):
        """
        Create a child command

        :param name: Name of the command
        """
        def decorator(cls):
            self.children.append(CLITree(
                name=name,
                fullname=f'{self.fullname} {name}' if not self.root else f'{name}',
                cls=cls))
            return cls
        return decorator


class CustomNestedCompleter(NestedCompleter):
    """
    Copy of the NestedCompleter class that accepts a CLITree object and
    supports meta_dict for descriptions
    """

    def __init__(
        self, options, ignore_case: bool = True, meta_dict: dict = {}
    ) -> None:
        self.options = options
        self.ignore_case = ignore_case
        self.meta_dict = meta_dict

    def __repr__(self) -> str:
        return f"CustomNestedCompleter({self.options!r}, ignore_case={self.ignore_case!r})"

    @classmethod
    def from_clitree(cls, node):
        options = {}
        meta_dict = {}

        for child_node in node.children:
            if child_node.cls:
                # CLITree is a standalone command with arguments
                options[child_node.name] = ArgparseCompleter(
                    child_node.cls().args_parser())
            else:
                # CLITree is a command group
                options[child_node.name] = cls.from_clitree(child_node)
                meta_dict[child_node.name] = child_node.help_text

        return cls(options, meta_dict=meta_dict)

    def get_completions(self, document, complete_event):
        # Split document.
        text = document.text_before_cursor.lstrip()
        stripped_len = len(document.text_before_cursor) - len(text)

        # If there is a space, check for the first term, and use a sub_completer.
        if " " in text:
            first_term = text.split()[0]
            completer = self.options.get(first_term)

            # If we have a sub completer, use this for the completions.
            if completer is not None:
                remaining_text = text[len(first_term):].lstrip()
                move_cursor = len(text) - len(remaining_text) + stripped_len

                new_document = Document(
                    remaining_text,
                    cursor_position=document.cursor_position - move_cursor,
                )

                yield from completer.get_completions(new_document, complete_event)

        # No space in the input: behave exactly like `WordCompleter`.
        else:
            completer = WordCompleter(
                list(self.options.keys()), ignore_case=self.ignore_case, meta_dict=self.meta_dict
            )
            yield from completer.get_completions(document, complete_event)


class ArgparseCompleter(Completer):
    """
    Completer instance for autocompletion of ArgumentParser arguments

    :param parser: ArgumentParser instance
    """

    def __init__(self, parser) -> None:
        self.parser: ArgumentParserNoExit = parser
        self._option_map = {}
        for action in self.parser._actions:
            for opt in action.option_strings:
                self._option_map[opt] = action

    @staticmethod
    def _value_count(action) -> Optional[int]:
        if action.nargs in (None, 1, "?"):
            return 1
        if action.nargs == 0:
            return 0
        if isinstance(action.nargs, int):
            return action.nargs
        return None

    def _suggest_options(self, prefix: str):
        suggestions = {}
        for action in self.parser._actions:
            for opt in action.option_strings:
                if opt.startswith(prefix):
                    suggestions[opt] = action.help
        return suggestions

    @staticmethod
    def _suggest_choices(action, prefix: str):
        suggestions = {}
        if not action.choices:
            return suggestions
        for choice in action.choices:
            choice_text = str(choice)
            if choice_text.startswith(prefix):
                suggestions[choice_text] = None
        return suggestions

    def _analyze_tokens(self, text: str):
        tokens = text.split()
        trailing_space = text.endswith(" ")
        current_fragment = "" if trailing_space else (tokens.pop() if tokens else "")
        expecting_action = None
        remaining_values = 0

        index = 0
        while index < len(tokens):
            token = tokens[index]

            if expecting_action is not None and remaining_values != 0:
                if token.startswith("-") and token in self._option_map:
                    expecting_action = None
                    remaining_values = 0
                    continue
                if remaining_values is not None:
                    remaining_values -= 1
                    if remaining_values <= 0:
                        expecting_action = None
                        remaining_values = 0
                index += 1
                continue

            action = self._option_map.get(token)
            if action is not None:
                expecting_action = action
                remaining_values = self._value_count(action) or 0
                if remaining_values == 0:
                    expecting_action = None
                index += 1
                continue

            index += 1

        return expecting_action, current_fragment

    def check_tokens(self, text: str):
        expecting_action, current_fragment = self._analyze_tokens(text)
        if expecting_action is not None and not current_fragment.startswith("-"):
            suggestions = self._suggest_choices(expecting_action, current_fragment)
            return suggestions
        return self._suggest_options(current_fragment)

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        word_before_cursor = document.text_before_cursor.split(' ')[-1]

        suggestions = self.check_tokens(text)

        for key, suggestion in suggestions.items():
            yield Completion(key, -len(word_before_cursor), display=key, display_meta=suggestion)

class ArgumentParserNoExit(argparse.ArgumentParser):
    """
        If arg ArgumentParser parse error, we can't exit process,
        we must raise exception to stop parse
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_help = False
        self.description = "Please enter correct parameters"
        self.help_requested = False

    def exit(self, status: int = 0, message: Union[str, None] = None):
        if message:
            raise ParserExitIntercept(message)

    def error(self, message: str):
        args = {'prog': self.prog, 'message': message}
        raise ArgsParserError('%(prog)s: error: %(message)s\n' % args)

    def print_help(self):
        """
        Colorize argparse help
        """
        print("-" * 80)
        print(f"{CR}{self.prog}{C0}\n")
        lines = self.format_help().splitlines()
        usage = lines[:lines.index('')]
        assert usage[0].startswith('usage:')
        usage[0] = usage[0].replace('usage:', f'{CG}usage:{C0}\n ')
        usage[0] = usage[0].replace(self.prog, f'{CR}{self.prog}{C0}')
        usage = [usage[0]] + [x[4:] for x in usage[1:]] + ['']
        lines = lines[lines.index('')+1:]
        desc = lines[:lines.index('')]
        print(f'{CC}'+'\n'.join(desc)+f'{C0}\n')
        print('\n'.join(usage))
        lines = lines[lines.index('')+1:]
        if '' in lines:
            options = lines[:lines.index('')]
            lines = lines[lines.index('')+1:]
        else:
            options = lines
            lines = []
        if len(options) > 0 and options[0].strip() == 'positional arguments:':
            positional_args = options
            positional_args[0] = positional_args[0].replace('positional arguments:', f'{CG}positional arguments:{C0}')
            if len(positional_args) > 1:
                positional_args.append('')
            print('\n'.join(positional_args))
            if '' in lines:
                options = lines[:lines.index('')]
                lines = lines[lines.index('')+1:]
            else:
                options = lines
                lines = []
        if len(options) > 0:
            # 2 variants depending on Python version(?)
            assert options[0].strip() in ['options:', 'optional arguments:']
            options[0] = options[0].replace('options:', f'{CG}options:{C0}')
            options[0] = options[0].replace('optional arguments:', f'{CG}optional arguments:{C0}')
            if len(options) > 1:
                options.append('')
            print('\n'.join(options))
        if len(lines) > 0:
            lines[0] = f'{CG}{lines[0]}{C0}'
            print('\n'.join(lines))
        print('')
        self.help_requested = True

class NdefParser:
    """
    Class for parsing binary data into NDEF records
    """
    def __init__(self, bindata):
        self.bindata = bindata
        self.records = []
        self.urls = []
        self.parse_records()

    def parse_records(self):
        """
        Parse NDEF records from binary data, specifically handling Mifare Ultralight dumps
        """
        self.records = []
        self.urls = []
        i = 16
        while i < len(self.bindata):
            try:
            # Search for a potential NDEF record start
                if self.bindata[i] & 0x07 in [0x01, 0x03]:
                    type_length = self.bindata[i + 1]
                    payload_length = self.bindata[i + 2]
                    type_start = i + 3
                    payload_start = type_start + type_length
                    payload_end = payload_start + payload_length

                    if payload_end > len(self.bindata):
                        i +=1
                        continue
                    record_type = self.bindata[type_start:type_start + type_length]
                    payload = self.bindata[payload_start:payload_end]

                    if record_type == b'U':  # URI Record
                        self.records.append(payload)
                        decoded_uri = self._decode_uri(payload)
                        self.urls.append(decoded_uri)
                        # print(f"Decoded URI: {decoded_uri}")
                        i = payload_end
            except Exception as e:
                print(f"Error parsing record at byte {i}: {e}")
            i += 1

    def _decode_uri(self, payload):
        """
        Decode a URI payload according to the NDEF URI Record specification
        """
        uri_prefixes = [
            "", "http://www.", "https://www.", "http://", "https://",
            "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
            "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
            "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
            "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://",
            "tcpobex://", "irdaobex://", "file://", "urn:epc:id:",
            "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
            "urn:nfc:"
        ]

        prefix_index = payload[0]
        uri = uri_prefixes[prefix_index] + payload[1:].decode('utf-8')
        return uri

    def get_urls(self):
        """
        Return the list of extracted URLs
        """
        return self.urls

