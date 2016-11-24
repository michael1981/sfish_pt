
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18421);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-416: kdbg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-416");
 script_set_attribute(attribute: "description", value: '
  An updated kdbg package that fixes a minor security issue is now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Kdbg is a K Desktop Environment (KDE) GUI for gdb, the GNU debugger.

  Kdbg 1.1.0 through 1.2.8 does not check permissions of the .kdbgrc file.
  If a program is located in a world-writable location, it is possible for a
  local user to inject malicious commands. These commands are then executed
  with the permission of any user that runs Kdbg. The Common Vulnerabilities
  and Exposures project assigned the name CAN-2003-0644 to this issue.

  Users of Kdbg should upgrade to this updated package, which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-416.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0644");
script_summary(english: "Check for the version of the kdbg packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdbg-1.2.1-7", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
