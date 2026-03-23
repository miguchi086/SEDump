#!/usr/bin/python3
# Copyright 2015 Fernand Lone Sang (Ge0n0sis)
# Copyright 2019 Raphaël Rigo
# Copyright 2026 みぐち
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.

import setools
import argparse
import sys
import logging
import re

from setools.policyrep import *


class SELinuxPolicy(setools.SELinuxPolicy):

    def __str__(self):

        sort = True

        def cond_sort(value):
            return value if not sort else sorted(value)

        def block_comment(text):
            inner = ''.join("# {0}\n".format(line) for line in text.splitlines())
            return "#\n{0}#\n\n".format(inner)

        out = []

        out.append(block_comment("Define the security object classes"))
        for class_ in cond_sort(self.classes()):
            out.append("class {0}\n".format(class_))
        out.append("\n")

        out.append(block_comment("Define the initial security identifiers"))
        for sid_ in cond_sort(self.initialsids()):
            out.append("sid {0}\n".format(sid_))
        out.append("\n")

        out.append(block_comment("Define common prefixes for access vectors"))
        for common_ in cond_sort(self.commons()):
            out.append("{0}\n\n".format(common_.statement()))

        out.append(block_comment("Define the access vectors"))
        for class_ in cond_sort(self.classes()):
            out.append("{0}\n{1}".format(
                class_.statement(),
                "\n" if len(class_.perms) > 0 else ""))

        out.append(block_comment("Define MLS sensitivities, categories and levels"))
        for sensitivity_ in cond_sort(self.sensitivities()):
            out.append("{0}\n".format(sensitivity_.statement()))
        out.append("\n")

        sensitivities_ = [str(x) for x in sorted(self.sensitivities())]
        out.append("dominance {{ {0} }}\n\n".format(' '.join(sensitivities_)))

        for category_ in cond_sort(self.categories()):
            out.append("category {0};\n".format(category_))
        out.append("\n")

        for level_ in cond_sort(self.levels()):
            out.append("{0}\n".format(level_.statement()))
        out.append("\n")
        
        out.append(block_comment("Define MLS policy constraints"))
        for mlscon_ in cond_sort(self.constraints()):
            out.append("{0}\n".format(mlscon_.statement()))
        out.append("\n")

        out.append(block_comment("Define policy capabilities"))
        for policycap_ in cond_sort(self.polcaps()):
            out.append("{0}\n".format(policycap_.statement()))
        out.append("\n")
        
        out.append(block_comment("Define attribute identifiers"))
        for attribute_ in cond_sort(self.typeattributes()):
            out.append("{0}\n".format(attribute_.statement()))
        out.append("\n")


        out.append(block_comment("Define type identifiers"))
        for type_ in cond_sort(self.types()):
            out.append("{0}\n".format(type_.statement()))
        out.append("\n")

        out.append(block_comment("Define booleans"))
        for bool_ in cond_sort(self.bools()):
            out.append("{0}\n".format(bool_.statement()))
        out.append("\n")

        out.append(block_comment("Define type enforcement rules"))
        for terule_ in cond_sort(self.terules()):
            rule_ = str(terule_)
            try:
                out.append("if ({0}) {{\n"
                           "    {1}\n"
                           "}}\n".format(terule_.conditional, rule_))
            except RuleNotConditional:
                out.append("{0}\n".format(rule_))
        out.append("\n")

        out.append(block_comment("Define roles identifiers"))
        for role_ in cond_sort(self.roles()):
            out.append("role {0};\n".format(role_))
            for type_ in role_.types():
                out.append("role {0} types {1};\n".format(role_, type_))
            out.append("\n")
        out.append("\n")

        out.append(block_comment("Define users"))
        for user_ in cond_sort(self.users()):
            out.append("{0}\n".format(user_.statement()))
        out.append("\n")

        out.append(block_comment("Define the initial sid contexts"))
        for sid_ in cond_sort(self.initialsids()):
            out.append("{0}\n".format(sid_.statement()))
        out.append("\n")

        out.append(block_comment("Label inodes via fs_use_xxx"))
        for fs_use_ in cond_sort(self.fs_uses()):
            out.append("{0}\n".format(fs_use_.statement()))
        out.append("\n")
        
        out.append(block_comment("Label inodes via genfscon"))
        for genfscon_ in cond_sort(self.genfscons()):
            out.append("{0}\n".format(genfscon_.statement()))
        out.append("\n")
       
        out.append(block_comment("Label ports via portcon"))
        for portcon_ in cond_sort(self.portcons()):
            out.append("{0}\n".format(portcon_.statement()))
        out.append("\n")

        _xperm_re = re.compile(
            r'^((?:allow|dontaudit|neverallow|auditallow)xperm\s+\S+\s+\S+\s+\S+\s+)(\S+);$',
            re.MULTILINE
        )
        def _add_xperm_braces(m):
            val = m.group(2)
            if val.startswith('{'):
                return m.group(0)
            return "{0}{{ {1} }};".format(m.group(1), val)

        result = ''.join(out)
        result = _xperm_re.sub(_add_xperm_braces, result)
        
        result = re.sub(r'\[(\w+)\]', r'\1', result)
        
        result = re.sub(
            r'^(type_transition\s+\S+\s+\S+\s+\S+\s+)(\w+)(;)',
            r'\1"\2"\3',
            result,
            flags=re.MULTILINE,
        )
        return result

parser = argparse.ArgumentParser(description="Binary SELinux policy dumping tool.")
parser.add_argument("-o", dest="output", default=None, help="Output file")
parser.add_argument("policy", help="Path to the binary SELinux policy to convert.", nargs="?")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Print extra informational messages")
parser.add_argument("--debug", action="store_true", dest="debug", help="Enable debugging.")

args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s|%(levelname)s|%(name)s|%(message)s')
elif args.verbose:
    logging.basicConfig(level=logging.INFO, format='%(message)s')
else:
    logging.basicConfig(level=logging.WARNING, format='%(message)s')

try:
    p = SELinuxPolicy(args.policy)

    if args.output:
        output = open(args.output, "w", encoding="utf-8")
    else:
        output = sys.stdout

    with output as fout:
        fout.write(str(p))

except Exception as err:
    if args.debug:
        import traceback
        traceback.print_exc()
    else:
        logging.error(err)
    sys.exit(-1)
