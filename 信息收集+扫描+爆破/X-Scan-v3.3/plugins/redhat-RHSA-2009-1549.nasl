
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42359);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1549: wget");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1549");
 script_set_attribute(attribute: "description", value: '
  An updated wget package that fixes a security issue is now available for
  Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GNU Wget is a file retrieval utility that can use HTTP, HTTPS, and FTP.

  Daniel Stenberg reported that Wget is affected by the previously published
  "null prefix attack", caused by incorrect handling of NULL characters in
  X.509 certificates. If an attacker is able to get a carefully-crafted
  certificate signed by a trusted Certificate Authority, the attacker could
  use the certificate during a man-in-the-middle attack and potentially
  confuse Wget into accepting it by mistake. (CVE-2009-3490)

  Wget users should upgrade to this updated package, which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1549.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3490");
script_summary(english: "Check for the version of the wget packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wget-1.11.4-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.2-0.30E.1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.2-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.2-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.11.4-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
