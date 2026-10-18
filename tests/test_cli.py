"""The command line's own contract. Run: python3 -m unittest discover -s tests

locaudit once stopped with "AttributeError: 'Namespace' object has no attribute 'json'":
the function read args.json while its parser had no --json. Nothing ran, and 33 tests passed.
This test reads each command's source, collects the args.<name> it touches, and fails when the
parser would not supply one.
"""
import ast
import inspect
import textwrap
import unittest

from locaudit import cli

# What a command cannot be run without, so parsing can be checked with no phone and no run.
# A command missing from here takes no argument it must have.
REQUIRED = {
    "show": ["com.example.app"],
    "pull": ["com.example.app"],
    "inspect": ["com.example.app"],
    "page": ["com.example.app"],
    "pcap": ["traffic.pcap"],
}


def arguments_used(fn):
    """Every args.<name> the function reads, without running it."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    return {node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "args"}


class EveryCommandReadsItsArguments(unittest.TestCase):
    def setUp(self):
        self.parser = cli.build_parser()

    def test_the_parser_lists_its_commands(self):
        self.assertIn("location", cli.COMMANDS)
        for name, fn in cli.COMMANDS.items():
            with self.subTest(command=name):
                args = self.parser.parse_args([name] + REQUIRED.get(name, []))
                self.assertIs(args.fn, fn, f"locaudit {name} does not run the function it names")

    def test_every_command_can_read_the_arguments_it_uses(self):
        for name, fn in sorted(cli.COMMANDS.items()):
            with self.subTest(command=name):
                args = self.parser.parse_args([name] + REQUIRED.get(name, []))
                missing = sorted(arguments_used(fn) - set(vars(args)))
                self.assertEqual(
                    missing, [],
                    f"locaudit {name} reads args.{', args.'.join(missing)}, but its parser has no "
                    f"such argument; add it in locaudit/cli.py build_parser()")


if __name__ == "__main__":
    unittest.main()
