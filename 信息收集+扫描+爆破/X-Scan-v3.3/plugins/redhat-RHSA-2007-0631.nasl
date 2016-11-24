
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27832);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0631: coolkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0631");
 script_set_attribute(attribute: "description", value: '
  Updated coolkey packages that fix a security issue and various bugs are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red
  Hat Security Response Team.

  coolkey contains the driver support for the CoolKey and Common Access Card
  (CAC) Smart Card products. The CAC is used by the U.S. Government.

  Steve Grubb discovered a flaw in the way coolkey created a temporary
  directory. A local attacker could perform a symlink attack and cause
  arbitrary files to be overwritten. (CVE-2007-4129)

  In addition, the updated packages contain fixes for the following bugs in
  the CAC Smart Card support:

  * CAC Smart Cards can have from 1 to 3 certificates. The coolkey driver,
  however, was not recognizing cards if they had less than 3 certificates.

  * logging into a CAC Smart Card token with a new application would cause
  other, already authenticated, applications to lose their login status
  unless the Smart Card was then removed from the reader and re-inserted.

  All CAC users should upgrade to these updated packages, which resolve these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0631.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4129");
script_summary(english: "Check for the version of the coolkey packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"coolkey-1.1.0-5.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"coolkey-devel-1.1.0-5.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
