
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19542);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-267: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-267");
 script_set_attribute(attribute: "description", value: '
  Updated evolution packages that fix a format string issue are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Evolution is the GNOME collection of personal information management (PIM)
  tools.

  A format string bug was found in Evolution. If a user tries to save a
  carefully crafted meeting or appointment, arbitrary code may be executed as
  the user running Evolution. The Common Vulnerabilities and Exposures
  project has assigned the name CAN-2005-2550 to this issue.

  Additionally, several other format string bugs were found in Evolution. If
  a user views a malicious vCard, connects to a malicious LDAP server, or
  displays a task list from a malicious remote server, arbitrary code may be
  executed as the user running Evolution. The Common Vulnerabilities and
  Exposures project has assigned the name CAN-2005-2549 to this issue. Please
  note that this issue only affects Red Hat Enterprise Linux 4.

  All users of Evolution should upgrade to these updated packages, which
  contain a backported patch which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-267.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2549", "CVE-2005-2550");
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

if ( rpm_check( reference:"evolution-1.4.5-16", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-1.4.5-16", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-2.0.2-16.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.2-16.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
