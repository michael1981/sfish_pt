
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19994);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-709: gdb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-709");
 script_set_attribute(attribute: "description", value: '
  An updated gdb package that fixes several bugs and minor security issues is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GDB, the GNU debugger, allows debugging of programs written in C, C++,
  and other languages by executing them in a controlled fashion, then
  printing their data.

  Several integer overflow bugs were found in gdb. If a user is tricked
  into processing a specially crafted executable file, it may allow the
  execution of arbitrary code as the user running gdb. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-1704 to this issue.

  A bug was found in the way gdb loads .gdbinit files. When a user executes
  gdb, the local directory is searched for a .gdbinit file which is then
  loaded. It is possible for a local user to execute arbitrary commands as
  the victim running gdb by placing a malicious .gdbinit file in a location
  where gdb may be run. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-1705 to this issue.

  This updated package also addresses the following issues:

  - GDB on ia64 had previously implemented a bug fix to work-around a kernel
  problem when creating a core file via gcore. The bug fix caused a
  significant slow-down of gcore.

  - GDB on ia64 issued an extraneous warning when gcore was used.

  - GDB on ia64 could not backtrace over a sigaltstack.

  - GDB on ia64 could not successfully do an info frame for a signal
  trampoline.

  - GDB on AMD64 and Intel EM64T had problems attaching to a 32-bit process.

  - GDB on AMD64 and Intel EM64T was not properly handling threaded
  watchpoints.

  - GDB could not build with gcc4 when -Werror flag was set.

  - GDB had problems printing inherited members of C++ classes.

  - A few updates from mainline sources concerning Dwarf2 partial die in
  cache support, follow-fork support, interrupted syscall support, and
  DW_OP_piece read support.

  All users of gdb should upgrade to this updated package, which resolves
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-709.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1704", "CVE-2005-1705");
script_summary(english: "Check for the version of the gdb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gdb-6.3.0.0-1.63", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
