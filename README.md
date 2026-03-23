# SEDump
Sepolicy dumper written in Python

### Changes from original script:
- Changed output file mode from "wb" (binary) to "w" with UTF-8 encoding.

- Adjusted the outputted lines to be 1:1 of the original policy. Previously, it outputs lines with wrong syntax, prompting the user to correct them since the compiler won't accept it anyway. I'm so tired of doing that.

- Added braces around the permission operand in allowxperm, dontauditxperm, auditallowxperm, and neverallowxperm statements. Original setool outputs these rules without braces (e.g., ioctl 0xc300-0xc305), but checkpolicy requires them to be wrapped in braces even for single values or ranges.

- Removed square bracket notation from type and class names. Setools 4.x displays some types as [foo] in rules, which is an internal display convention, not valid policy syntax. A regex pass strips brackets from tokens so that [foo] becomes foo, allowing checkpolicy to parse the rule.

- Quoted the object name in the four-argument form of type_transition. Setools emits the object name as a bare identifier (e.g., type_transition, bluetooth_userfaultfd userfaultfd) but checkpolicy expects a quoted string in that position.

- Replaced incremental string concatenation with list accumulation when building the final output to decrease the compilation time (barely noticeable). The original loop used output += new_text across the rules, resulting in time complexity since the whole stuff is very long.

- Renamed the inner helper comment() to block_comment(), in order to make the code clearer to read.

### Usage:
```
python sedump.py <compiled_sepolicy> -o <file_name.conf>
```
### To compile:
```
checkpolicy -M -c 30 -t selinux -S -O -o <compiled_sepolicy> <file_name.conf>
```
- [checkpolicy guide](https://man7.org/linux/man-pages/man8/checkpolicy.8.html)
- [original sedump repo](https://github.com/trou/sedump)
