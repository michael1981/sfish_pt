
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38732);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0476: pango");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0476");
 script_set_attribute(attribute: "description", value: '
  Updated pango and evolution28-pango packages that fix an integer overflow
  flaw are now available for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Pango is a library used for the layout and rendering of internationalized
  text.

  Will Drewry discovered an integer overflow flaw in Pango\'s
  pango_glyph_string_set_size() function. If an attacker is able to pass an
  arbitrarily long string to Pango, it may be possible to execute arbitrary
  code with the permissions of the application calling Pango. (CVE-2009-1194)

  pango and evolution28-pango users are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. After
  installing this update, you must restart your system or restart the X
  server for the update to take effect. Note: Restarting the X server closes
  all open applications and logs you out of your session.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0476.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1194");
script_summary(english: "Check for the version of the pango packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pango-1.14.9-5.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pango-devel-1.14.9-5.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pango-1.2.5-8", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pango-devel-1.2.5-8", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution28-pango-1.14.9-11.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution28-pango-devel-1.14.9-11.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pango-1.6.0-14.4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pango-devel-1.6.0-14.4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
