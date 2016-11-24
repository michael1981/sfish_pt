
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12445);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-002: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-002");
 script_set_attribute(attribute: "description", value: '
  Updated Ethereal packages that fix two security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  Two security issues have been found that affect Ethereal. By exploiting
  these issues it may be possible to make Ethereal crash by injecting an
  intentionally malformed packet onto the wire or by convincing someone to
  read a malformed packet trace file. It is not known if these issues could
  allow arbitrary code execution.

  The SMB dissector in Ethereal before 0.10.0 allows remote attackers to
  cause a denial of service via a malformed SMB packet that triggers a
  segmentation fault during processing of Selected packets. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-1012 to this issue.

  The Q.931 dissector in Ethereal before 0.10.0 allows remote attackers to
  cause a denial of service (crash) via a malformed Q.931, which triggers a
  null dereference. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-1013 to this issue.

  Users of Ethereal should update to these erratum packages containing
  Ethereal version 0.10.0, which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-002.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-1012", "CVE-2003-1013");
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

if ( rpm_check( reference:"ethereal-0.10.0a-0.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.0a-0.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.0a-0.30E.1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.0a-0.30E.1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
