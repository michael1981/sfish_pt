
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12433);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-324: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-324");
 script_set_attribute(attribute: "description", value: '
  Updated Ethereal packages that fix a number of exploitable security issues
  are now available.

  Ethereal is a program for monitoring network traffic.

  A number of security issues affect Ethereal. By exploiting these issues,
  it may be possible to make Ethereal crash or run arbitrary code by
  injecting a purposefully-malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file.

  A buffer overflow in Ethereal 0.9.15 and earlier allows remote attackers
  to cause a denial of service and possibly execute arbitrary code via a
  malformed GTP MSISDN string. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2003-0925 to
  this issue.

  Ethereal 0.9.15 and earlier allows remote attackers to cause a denial of
  service (crash) via certain malformed ISAKMP or MEGACO packets. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0926 to this issue.

  A heap-based buffer overflow in Ethereal 0.9.15 and earlier allows
  remote attackers to cause a denial of service (crash) and possibly
  execute arbitrary code via the SOCKS dissector. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2003-0927
  to this issue.

  Users of Ethereal should update to these erratum packages containing
  Ethereal version 0.9.16, which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-324.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927");
script_summary(english: "Check for the version of the ethereal packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.9.16-0.AS21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.16-0.AS21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.16-0.30E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.16-0.30E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
