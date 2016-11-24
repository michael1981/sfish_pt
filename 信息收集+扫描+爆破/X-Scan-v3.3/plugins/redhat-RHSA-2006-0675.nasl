
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22357);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0675: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0675");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Two flaws were found in the way Firefox processed certain regular
  expressions. A malicious web page could crash the browser or possibly
  execute arbitrary code as the user running Firefox. (CVE-2006-4565,
  CVE-2006-4566)

  A number of flaws were found in Firefox. A malicious web page could crash
  the browser or possibly execute arbitrary code as the user running Firefox.
  (CVE-2006-4571)

  A flaw was found in the handling of Javascript timed events. A malicious
  web page could crash the browser or possibly execute arbitrary code as the
  user running Firefox. (CVE-2006-4253)

  Daniel Bleichenbacher recently described an implementation error in RSA
  signature verification. For RSA keys with exponent 3 it is possible for an
  attacker to forge a signature that would be incorrectly verified by the NSS
  library. Firefox as shipped trusts several root Certificate Authorities
  that use exponent 3. An attacker could have created a carefully crafted
  SSL certificate which be incorrectly trusted when their site was visited by
  a victim. (CVE-2006-4340)

  A flaw was found in the Firefox auto-update verification system. An
  attacker who has the ability to spoof a victim\'s DNS could get Firefox to
  download and install malicious code. In order to exploit this issue an
  attacker would also need to get a victim to previously accept an
  unverifiable certificate. (CVE-2006-4567)

  Firefox did not properly prevent a frame in one domain from injecting
  content into a sub-frame that belongs to another domain, which facilitates
  website spoofing and other attacks (CVE-2006-4568)

  Firefox did not load manually opened, blocked popups in the right domain
  context, which could lead to cross-site scripting attacks. In order to
  exploit this issue an attacker would need to find a site which would frame
  their malicious page and convince the user to manually open a blocked
  popup. (CVE-2006-4569)

  Users of Firefox are advised to upgrade to this update, which contains
  Firefox version 1.5.0.7 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0675.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4568", "CVE-2006-4569", "CVE-2006-4571");
script_summary(english: "Check for the version of the firefox packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"firefox-1.5.0.7-0.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
