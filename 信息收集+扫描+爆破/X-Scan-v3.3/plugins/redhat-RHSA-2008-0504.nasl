
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33153);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0504: xorg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0504");
 script_set_attribute(attribute: "description", value: '
  Updated xorg-x11-server packages that fix several security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  X.Org is an open source implementation of the X Window System. It provides
  basic low-level functionality that full-fledged graphical user interfaces
  are designed upon.

  An input validation flaw was discovered in X.org\'s Security and Record
  extensions. A malicious authorized client could exploit this issue to cause
  a denial of service (crash) or, potentially, execute arbitrary code with
  root privileges on the X.Org server. (CVE-2008-1377)

  Multiple integer overflow flaws were found in X.org\'s Render extension. A
  malicious authorized client could exploit these issues to cause a denial of
  service (crash) or, potentially, execute arbitrary code with root
  privileges on the X.Org server. (CVE-2008-2360, CVE-2008-2361,
  CVE-2008-2362)

  An input validation flaw was discovered in X.org\'s MIT-SHM extension. A
  client connected to the X.org server could read arbitrary server memory.
  This could result in the sensitive data of other users of the X.org server
  being disclosed. (CVE-2008-1379)

  Users of xorg-x11-server should upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0504.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
script_summary(english: "Check for the version of the xorg packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xorg-x11-server-Xdmx-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xephyr-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xnest-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xorg-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xvfb-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-randr-source-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-sdk-1.1.1-48.41.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
