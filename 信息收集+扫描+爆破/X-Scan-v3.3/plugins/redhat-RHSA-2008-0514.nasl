
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33086);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2008-0514: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0514");
 script_set_attribute(attribute: "description", value: '
  Updated evolution packages that fix two buffer overflow vulnerabilities are
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Evolution is the integrated collection of e-mail, calendaring, contact
  management, communications and personal information management (PIM) tools
  for the GNOME desktop environment.

  A flaw was found in the way Evolution parsed iCalendar timezone attachment
  data. If the Itip Formatter plug-in was disabled and a user opened a mail
  with a carefully crafted iCalendar attachment, arbitrary code could be
  executed as the user running Evolution. (CVE-2008-1108)

  Note: the Itip Formatter plug-in, which allows calendar information
  (attachments with a MIME type of "text/calendar") to be displayed as part
  of the e-mail message, is enabled by default.

  A heap-based buffer overflow flaw was found in the way Evolution parsed
  iCalendar attachments with an overly long "DESCRIPTION" property string. If
  a user responded to a carefully crafted iCalendar attachment in a
  particular way, arbitrary code could be executed as the user running
  Evolution. (CVE-2008-1109).

  The particular response required to trigger this vulnerability was as
  follows:

  1. Receive the carefully crafted iCalendar attachment.
  2. Accept the associated meeting.
  3. Open the calender the meeting was in.
  4. Reply to the sender.

  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly disclosing these issues.

  All Evolution users should upgrade to these updated packages, which contain
  backported patches which resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0514.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1108", "CVE-2008-1109");
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

if ( rpm_check( reference:"evolution-2.12.3-8.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-help-2.12.3-8.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
