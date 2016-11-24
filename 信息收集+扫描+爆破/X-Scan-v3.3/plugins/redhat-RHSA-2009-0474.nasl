
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38710);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0474: acpid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0474");
 script_set_attribute(attribute: "description", value: '
  An updated acpid package that fixes one security issue is now available
  for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  acpid is a daemon that dispatches ACPI (Advanced Configuration and Power
  Interface) events to user-space programs.

  Anthony de Almeida Lopes of Outpost24 AB reported a denial of service flaw
  in the acpid daemon\'s error handling. If an attacker could exhaust the
  sockets open to acpid, the daemon would enter an infinite loop, consuming
  most CPU resources and preventing acpid from communicating with legitimate
  processes. (CVE-2009-0798)

  Users are advised to upgrade to this updated package, which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0474.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0798");
script_summary(english: "Check for the version of the acpid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"acpid-1.0.4-7.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acpid-1.0.3-2.el4_7.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
