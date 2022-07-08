Linux Security Module Subsystem
=============================================================================
https://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/lsm.git  
https://github.com/LinuxSecurityModule/kernel

The Linux Security Module (LSM) subsystem is a modular access control framework
design to allow multiple security models to be implemented inside of the Linux
kernel; popular LSMs include SELinux, AppArmor, and Smack.

The main Linux kernel README can be found at
[Documentation/admin-guide/README.rst](./Documentation/admin-guide/README.rst)

## Online Resources

The canonical LSM kernel repository is hosted by kernel.org:

* https://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/lsm.git
* git://git.kernel.org/pub/scm/linux/kernel/git/pcmoore/lsm.git

There is also an officially maintained GitHub mirror:

* https://github.com/LinuxSecurityModule/kernel

The LSM mailing list can be found at the link below:
* http://vger.kernel.org/vger-lists.html#linux-security-module

The official LSM mailing list archive can be found at the link below:
* https://lore.kernel.org/linux-security-module

## Kernel Tree Process

After the merge window closes upstream, a decision will be made regarding the
need to rebase the next branch on top of the current Linux -rc1 release. If
there have been a number of subsystem related changes outside of the
subsystem's next branch, or if the branch's base is too far behind
linux/master, it may be necessary to rebase the next branch. If a rebase is
needed, it should be done before any patches are merged, and rebasing the next
branch during the remaining -rcX releases should only be done in extreme cases.

Patches will be merged into the subsystem's next branch during the development
cycle which extends from merge window close up until the merge window reopens.
However, it is important to note that large, complicated, or invasive patches
sent late in the development cycle may be deferred until the next cycle. As a
general rule, only small patches or critical fixes will be merged after
-rc5/-rc6.

Any patches deemed necessary for the current Linux -rcX releases will be merged
into the current stable-X.Y branch, marked with a signed tag, and a pull
request sent against linux/master as soon as it is reasonable to do so.

During the development cycle Fedora Rawhide test kernels will be generated
using the next and most recent stable-X.Y branches on a weekly basis, if not
more often. These kernels will be tested against the SELinux test suite and
audit test suite as well as being made available to everyone for additional
testing.

Once the merge window opens, the next branch will be copied to a new branch,
stable-X.Y, and the branch will be marked with a signed tag in the format
lsm-pr-YYYYMMDD. A pull request will be sent against the linux/master
branch using the signed tag.

## New LSM Hook Guidelines

While LSM hooks are considered outside of the Linux kernel's stable API
promise, in order to limit unnecessary churn within the kernel we do try to
minimize changes to the set of LSM hooks.  With that in mind, we have the
following requirements for new LSM hooks:

* Hooks should be designed to be LSM agnostic.  While it is possible that only
one LSM might implement the hook at the time of submission, the hook's behavior
should be generic enough that other LSMs could provide a meaningful
implementation.

* The hook must be documented with a function header block that conforms to
the kernel documentation style.  At a minimum the documentation should explain
the parameters, return values, a brief overall description, any special
considerations for the callers, and any special considerations for the LSM
implementations.

* New LSM hooks must demonstrate their usefulness by providing a meaningful
implementation for at least one in-kernel LSM.  The goal is to demonstrate the
purpose and expected semantics of the hooks.  Out of tree kernel code, and pass
through implementations, such as the BPF LSM, are not eligible for LSM hook
reference implementations.

It is important to note that these requirements are not complete, due to the
ever changing nature of the Linux kernel and the unique nature of each LSM
hook.  Ultimately, new LSM hooks are added to the kernel at the discretion of
the maintainers and reviewers.

## New LSM Guidelines

Historically we have had few requirements around new LSM additions, with
Arjan van de Ven being the first to describe a basic protocol for accepting new
LSMs into the Linux kernel[^1].  In an attempt to document Arjan's basic ideas
and update them for modern Linux kernel development, here are a list of
requirements for new LSM submissions:

* The new LSM's author(s) must commit to maintain and support the new LSM for
an extended period of time.  While the authors may be currently employed to
develop and support the LSM, there is an expectation upstream that support will
continue beyond the author's employment with the original company, or the
company's backing of the LSM.

* The new LSM must be sufficiently unique to justify the additional work
involved in reviewing, maintaining, and supporting the LSM.  It is reasonable
for there to be a level of overlap between LSMs, but either the security model
or the admin/user experience must be significantly unique.

* New LSMs must include documentation providing a clear explanation of the
LSM's requirements, goals, and expected uses.  The documentation does not need
to rise to the level of a formal security model, but it should include a basic
threat model with a description of the mitigations provided by the LSM.  Both
the threat model and the LSM mitigations must be considered "reasonable" by
the LSM community as a whole.

* Any user visible interfaces provided by the LSM must be well documented.  It
is important to remember the user visible APIs are considered to be "forever
APIs" by the Linux kernel community; do not add an API that cannot be supported
for the next 20+ years.

* New LSMs must be accompanied by a publicly available test suite to verify
basic functionality and help identify regressions.  Test coverage does not need
to reach a specific percentage, but core functionality and any user interfaces
should be well covered by the test suite.  Maintaining the test suite in a
public git repository is preferable over tarball snapshots.  Integrating the
test suite with existing automated Linux kernel testing services is encouraged.

* The LSM implementation must follow general Linux kernel coding practices,
faithfully implement the security model and APIs described in the
documentation, and be free of any known defects at the time of submission.

* Any userspace tools or patches created in support of the LSM must be publicly
available, with a public git repository preferable over a tarball snapshot.

It is important to note that these requirements are not complete, due to the
ever changing nature of the Linux kernel and the unique nature of each LSM.
Ultimately, new LSMs are added to the kernel at the discretion of the
maintainers and reviewers.

[^1]: https://lore.kernel.org/all/20071026141358.38342c0f@laptopd505.fenrus.org
