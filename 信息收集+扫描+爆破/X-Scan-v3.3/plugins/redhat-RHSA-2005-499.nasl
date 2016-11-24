
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18473);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-499: gedit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-499");
 script_set_attribute(attribute: "description", value: '
  An updated gedit package that fixes a file name format string vulnerability
  is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team

  gEdit is a small text editor designed specifically for the GNOME GUI
  desktop.

  A file name format string vulnerability has been discovered in gEdit. It is
  possible for an attacker to create a file with a carefully crafted name
  which, when the file is opened, executes arbitrary instructions on a
  victim\'s machine. Although it is unlikely that a user would manually open a
  file with such a carefully crafted file name, a user could, for example, be
  tricked into opening such a file from within an email client. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-1686 to this issue.

  Users of gEdit should upgrade to this updated package, which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-499.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1686");
script_summary(english: "Check for the version of the gedit packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gedit-2.2.2-4.rhel3", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gedit-2.8.1-4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gedit-devel-2.8.1-4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
