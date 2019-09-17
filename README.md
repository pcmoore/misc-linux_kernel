Reworking the Linux Audit Subsystem
=============================================================================
https://github.com/pcmoore/misc-linux_kernel/tree/working-audit_rework_v1

*LAST UPDATED: December 6, 2021*

I often joke that the Linux Kernel's Audit Subsystem is a bad design,
implemented poorly; while this is definitely an extreme take on the audit
subsystem there is quite a bit of truth in that joke.  This kernel branch is
a first attempt at starting to fix some of these problems.

The intent is to use this file as a planning and tracking document for the
work and as a result I expect it to be a living document that will change
regularly as development progresses.  It is not intended to be the primary,
long term source of information on the audit rework but it may be the best
starting point for information while the audit rework patches remain
out-of-tree.

## Problems

A prioritized list of problems with the most serious issues at the top.  This
is not a complete list.

- The kernel/userspace ABI is too fragile and not easily extended.  The record
format is a human readable string composed of name/value pairs, which seems
reasonable at first glance but it presents a number of issues:
  - The string format is expensive to generate in the kernel.
  - The audit record parsing library makes assumptions on the ordering of
  fields in the record which make it difficult and/or awkward to extend
  individual audit records.
- Performance is poor.
- Code quality is poor.  This is a subjective assessment, but as someone who
has been maintaining the kernel audit code for some years I feel comfortable
making this judgment.

## Solutions

An unordered list of changes to the audit subsystem that are intended to help
resolve the problems listed above.  These ideas are subject to change at any
time.

- Replace `audit_log_format()`, and similar kernel APIs, with functions that
do not require the callers to format the data.  Separating the formatting of
the data from the data values themselves allows the audit subsystem to not
only provide multiple different output formats, it also allows the subsystem
to move the formatting out of the critical processing path and into a
dedicated audit thread.
- Provide a netlink attribute based audit record format in addition to the
string based format currently used by the audit subsystem.  The netlink
attribute based format should be more performant (easier to parse, more
compact) and easier to extend to meet future audit needs.  This would require
a new set of userspace tools which might be a good opportunity to introduce a
new audit userspace.
- In conjunction with the move to a netlink attribute based record format, move
the audit control API to a netlink attribute based API.  While performance is
much less of a concern, extensibility is critical.  This also would require a
new audit userspace (see previous bullet points).
- Evaluate the audit filtering mechanism and introduce a better, more
performant implementation.
- Evaluate the audit file watch capability to see if any improvements, either
in performance or code quality, can be made to the existing code.
- Consider exposing some configuration knob via sysfs and/or the kernel command
line to make it easier for distributions and administrators to configure audit
without dedicated audit userspace tooling.
- Consider moving the audit related source files from the "kernel/" directory
to a dedicated audit subdirectory, e.g. "kernel/audit/".
