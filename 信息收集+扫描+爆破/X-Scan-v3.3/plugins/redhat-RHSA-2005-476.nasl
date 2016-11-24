
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18409);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-476: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-476");
 script_set_attribute(attribute: "description", value: '
  Updated OpenSSL packages that fix security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3) and
  Transport Layer Security (TLS v1) protocols as well as a full-strength
  general purpose cryptography library.

  Colin Percival reported a cache timing attack that could allow a malicious
  local user to gain portions of cryptographic keys. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) assigned the name
  CAN-2005-0109 to the issue. The OpenSSL library has been patched to add a
  new fixed-window mod_exp implementation as default for RSA, DSA, and DH
  private-key operations. This patch is designed to mitigate cache timing
  and potentially related attacks.

  A flaw was found in the way the der_chop script creates temporary files. It
  is possible that a malicious local user could cause der_chop to overwrite
  files (CAN-2004-0975). The der_chop script was deprecated and has been
  removed from these updated packages. Red Hat Enterprise Linux 4 did not
  ship der_chop and is therefore not vulnerable to this issue.

  Users are advised to update to these erratum packages which contain patches
  to correct these issues.

  Please note: After installing this update, users are advised to either
  restart all services that use OpenSSL or restart their system.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-476.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0975", "CVE-2005-0109");
script_summary(english: "Check for the version of the openssl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openssl-0.9.6b-39", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-39", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-39", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-25.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-33.15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-16.22.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-43.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-43.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-43.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-22.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
