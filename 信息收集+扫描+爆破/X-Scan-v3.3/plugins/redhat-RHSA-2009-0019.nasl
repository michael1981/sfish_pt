
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35319);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0019: hanterm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0019");
 script_set_attribute(attribute: "description", value: '
  An updated hanterm-xf package to correct a security issue is now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Hanterm is a replacement for xterm, a X Window System terminal emulator,
  that supports Hangul input and output.

  A flaw was found in the Hanterm handling of Device Control Request Status
  String (DECRQSS) escape sequences. An attacker could create a malicious
  text file (or log entry, if unfiltered) that could run arbitrary commands
  if read by a victim inside a Hanterm window. (CVE-2008-2383)

  All hanterm-xf users are advised to upgrade to the updated package, which
  contains a backported patch to resolve this issue. All running instances of
  hanterm must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0019.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2383");
script_summary(english: "Check for the version of the hanterm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"hanterm-xf-2.0.5-5.AS21.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
