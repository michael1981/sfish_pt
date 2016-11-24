
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35302);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0018: xterm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0018");
 script_set_attribute(attribute: "description", value: '
  An updated xterm package to correct a security issue is now available for
  Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The xterm program is a terminal emulator for the X Window System.

  A flaw was found in the xterm handling of Device Control Request Status
  String (DECRQSS) escape sequences. An attacker could create a malicious
  text file (or log entry, if unfiltered) that could run arbitrary commands
  if read by a victim inside an xterm window. (CVE-2008-2383)

  All xterm users are advised to upgrade to the updated package, which
  contains a backported patch to resolve this issue. All running instances of
  xterm must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0018.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2383");
script_summary(english: "Check for the version of the xterm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xterm-215-5.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xterm-179-11.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xterm-192-8.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
