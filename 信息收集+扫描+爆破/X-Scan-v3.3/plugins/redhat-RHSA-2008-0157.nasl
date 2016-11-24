
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31163);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0157: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0157");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems. The Internet Printing Protocol (IPP) is a
  standard network protocol for remote printing, as well as managing print
  jobs.

  A flaw was found in the way CUPS handles the addition and removal of remote
  shared printers via IPP. A remote attacker could send malicious UDP IPP
  packets causing the CUPS daemon to crash. (CVE-2008-0882)

  Note: the default configuration of CUPS on Red Hat Enterprise Linux 5 will
  only accept requests of this type from the local subnet. This issue did not
  affect the versions of CUPS as shipped with Red Hat Enterprise Linux 3 or
  4.

  All cups users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0157.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0882");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.2.4-11.14.el5_1.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.2.4-11.14.el5_1.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.2.4-11.14.el5_1.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-lpd-1.2.4-11.14.el5_1.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
