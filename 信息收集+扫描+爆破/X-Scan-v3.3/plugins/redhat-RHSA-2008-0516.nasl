
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33098);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0516: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0516");
 script_set_attribute(attribute: "description", value: '
  Updated evolution packages that address a buffer overflow vulnerability are
  now available for Red Hat Enterprise Linux 3 and Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Evolution is the integrated collection of e-mail, calendaring, contact
  management, communications and personal information management (PIM) tools
  for the GNOME desktop environment.

  A flaw was found in the way Evolution parsed iCalendar timezone attachment
  data. If mail which included a carefully crafted iCalendar attachment was
  opened, arbitrary code could be executed as the user running Evolution.
  (CVE-2008-1108)

  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly disclosing this issue.

  All users of Evolution should upgrade to these updated packages, which
  contains a backported patch which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0516.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1108");
script_summary(english: "Check for the version of the evolution packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"evolution-1.4.5-22.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-1.4.5-22.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-2.0.2-35.0.4.el4_6.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.2-35.0.4.el4_6.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
