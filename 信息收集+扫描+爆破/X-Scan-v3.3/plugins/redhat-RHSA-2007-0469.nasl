
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25481);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0469: gdb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0469");
 script_set_attribute(attribute: "description", value: '
  An updated gdb package that fixes a security issue and various bugs is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GDB, the GNU debugger, allows debugging of programs written in C, C++, and
  other languages by executing them in a controlled fashion and then printing
  their data.

  Various buffer overflows and underflows were found in the DWARF expression
  computation stack in GDB. If an attacker could trick a user into loading
  an executable containing malicious debugging information into GDB, they may
  be able to execute arbitrary code with the privileges of the user.
  (CVE-2006-4146)

  This updated package also addresses the following issues:

  * Support on 64-bit hosts shared libraries debuginfo larger than 2GB.

  * Fix a race occasionally leaving the detached processes stopped.

  * Fix segmentation fault on the source display by ^X 1.

  * Fix a crash on an opaque type dereference.

  All users of gdb should upgrade to this updated package, which contains
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0469.html");
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

if ( rpm_check( reference:"gdb-6.3.0.0-1.138.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
