
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25138);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0229: gdb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0229");
 script_set_attribute(attribute: "description", value: '
  An updated gdb package that fixes a security issue and various bugs is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GDB, the GNU debugger, allows debugging of programs written in C, C++, and
  other languages by executing them in a controlled fashion and then printing
  their data.

  Various buffer overflows and underflows were found in the DWARF expression
  computation stack in GDB. If a user loaded an executable containing
  malicious debugging information into GDB, an attacker might be able to
  execute arbitrary code with the privileges of the user. (CVE-2006-4146)

  This updated package also addresses the following issues:

  * Fixed bogus 0x0 unwind of the thread\'s topmost function clone(3).

  * Fixed deadlock accessing invalid address; for corrupted backtraces.

  * Fixed a race which occasionally left the detached processes stopped.

  * Fixed \'gcore\' command for 32bit debugged processes on 64bit hosts.

  * Added support for TLS \'errno\' for threaded programs missing its
  \'-debuginfo\' package..

  * Suggest TLS \'errno\' resolving by hand if no threading was found..

  * Added a fix to prevent stepping into asynchronously invoked signal
  handlers.

  * Added a fix to avoid false warning on shared objects bfd close on
  Itanium.

  * Fixed segmentation fault on the source display by ^X 1.

  * Fixed object names keyboard completion.

  * Added a fix to avoid crash of \'info threads\' if stale threads exist.

  * Fixed a bug where shared libraries occasionally failed to load .

  * Fixed handling of exec() called by a threaded debugged program.

  * Fixed rebuilding requirements of the gdb package itself on multilib
  systems.

  * Fixed source directory pathname detection for the edit command.

  All users of gdb should upgrade to this updated package, which contains
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0229.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4146");
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

if ( rpm_check( reference:"gdb-6.3.0.0-1.143.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
