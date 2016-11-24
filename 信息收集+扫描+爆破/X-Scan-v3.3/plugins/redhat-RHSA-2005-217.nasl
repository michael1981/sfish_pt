
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17267);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-217: gmc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-217");
 script_set_attribute(attribute: "description", value: '
  Updated mc packages that fix multiple security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Midnight Commander (mc) is a visual shell, much like a file manager.

  Several format string bugs were found in Midnight Commander. If a user is
  tricked by an attacker into opening a specially crafted path with mc, it
  may be possible to execute arbitrary code as the user running Midnight
  Commander. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-1004 to this issue.

  Several buffer overflow bugs were found in Midnight Commander. If a user is
  tricked by an attacker into opening a specially crafted file or path
  with mc, it may be possible to execute arbitrary code as the user running
  Midnight Commander. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1005 to this issue.

  A buffer underflow bug was found in Midnight Commander. If a malicious
  local user is able to modify the extfs.ini file, it could be possible to
  execute arbitrary code as a user running Midnight Commander. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1176 to this issue.

  Users of mc should upgrade to these updated packages, which contain a
  backported patch, and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-217.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1176");
script_summary(english: "Check for the version of the gmc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gmc-4.5.51-36.6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.51-36.6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mcserv-4.5.51-36.6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
