
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(13854);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-308: ipsec");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-308");
 script_set_attribute(attribute: "description", value: '
  An updated ipsec-tools package that fixes verification of X.509
  certificates in racoon is now available.

  IPSEC uses strong cryptography to provide both authentication and
  encryption services.

  When configured to use X.509 certificates to authenticate remote hosts,
  ipsec-tools versions 0.3.3 and earlier will attempt to verify that host
  certificate, but will not abort the key exchange if verification fails.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0607 to this issue.

  Users of ipsec-tools should upgrade to this updated package which contains
  a backported security patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-308.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0607");
script_summary(english: "Check for the version of the ipsec packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ipsec-tools-0.2.5-0.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
