
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35654);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0261: vnc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0261");
 script_set_attribute(attribute: "description", value: '
  Updated vnc packages to correct a security issue are now available for Red
  Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Virtual Network Computing (VNC) is a remote display system which allows you
  to view a computer\'s "desktop" environment not only on the machine where it
  is running, but from anywhere on the Internet and from a wide variety of
  machine architectures.

  An insufficient input validation flaw was discovered in the VNC client
  application, vncviewer. If an attacker could convince a victim to connect
  to a malicious VNC server, or when an attacker was able to connect to
  vncviewer running in the "listen" mode, the attacker could cause the
  victim\'s vncviewer to crash or, possibly, execute arbitrary code.
  (CVE-2008-4770)

  Users of vncviewer should upgrade to these updated packages, which contain
  a backported patch to resolve this issue. For the update to take effect,
  all running instances of vncviewer must be restarted after the update is
  installed.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0261.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4770");
script_summary(english: "Check for the version of the vnc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vnc-4.1.2-14.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-server-4.1.2-14.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-4.0-0.beta4.1.8", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-server-4.0-0.beta4.1.8", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-4.0-12.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-server-4.0-12.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
