
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22359);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0677: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0677");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Two flaws were found in the way Thunderbird processed certain regular
  expressions. A malicious HTML email could cause a crash or possibly
  execute arbitrary code as the user running Thunderbird. (CVE-2006-4565,
  CVE-2006-4566)

  A flaw was found in the Thunderbird auto-update verification system. An
  attacker who has the ability to spoof a victim\'s DNS could get Firefox to
  download and install malicious code. In order to exploit this issue an
  attacker would also need to get a victim to previously accept an
  unverifiable certificate. (CVE-2006-4567)

  A flaw was found in the handling of Javascript timed events. A malicious
  HTML email could crash the browser or possibly execute arbitrary code as
  the user running Thunderbird. (CVE-2006-4253)

  Daniel Bleichenbacher recently described an implementation error in RSA
  signature verification. For RSA keys with exponent 3 it is possible for an
  attacker to forge a signature that which would be incorrectly verified by
  the NSS library. (CVE-2006-4340)

  A flaw was found in Thunderbird that triggered when a HTML message
  contained a remote image pointing to a XBL script. An attacker could have
  created a carefully crafted message which would execute Javascript if
  certain actions were performed on the email by the recipient, even if
  Javascript was disabled. (CVE-2006-4570)

  A number of flaws were found in Thunderbird. A malicious HTML email could
  cause a crash or possibly execute arbitrary code as the user running
  Thunderbird. (CVE-2006-4571)

  Users of Thunderbird are advised to upgrade to this update, which contains
  Thunderbird version 1.5.0.7 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0677.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4570", "CVE-2006-4571");
script_summary(english: "Check for the version of the thunderbird packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"thunderbird-1.5.0.7-0.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
