
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38769);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0480: poppler");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0480");
 script_set_attribute(attribute: "description", value: '
  Updated poppler packages that fix multiple security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Poppler is a Portable Document Format (PDF) rendering library, used by
  applications such as Evince.

  Multiple integer overflow flaws were found in poppler. An attacker could
  create a malicious PDF file that would cause applications that use poppler
  (such as Evince) to crash or, potentially, execute arbitrary code when
  opened. (CVE-2009-0147, CVE-2009-1179, CVE-2009-1187, CVE-2009-1188)

  Multiple buffer overflow flaws were found in poppler\'s JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause applications
  that use poppler (such as Evince) to crash or, potentially, execute
  arbitrary code when opened. (CVE-2009-0146, CVE-2009-1182)

  Multiple flaws were found in poppler\'s JBIG2 decoder that could lead to the
  freeing of arbitrary memory. An attacker could create a malicious PDF file
  that would cause applications that use poppler (such as Evince) to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0166,
  CVE-2009-1180)

  Multiple input validation flaws were found in poppler\'s JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause applications
  that use poppler (such as Evince) to crash or, potentially, execute
  arbitrary code when opened. (CVE-2009-0800)

  Multiple denial of service flaws were found in poppler\'s JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause applications
  that use poppler (such as Evince) to crash when opened. (CVE-2009-0799,
  CVE-2009-1181, CVE-2009-1183)

  Red Hat would like to thank Braden Thomas and Drew Yao of the Apple Product
  Security team, and Will Dormann of the CERT/CC for responsibly reporting
  these flaws.

  Users are advised to upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0480.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187", "CVE-2009-1188");
script_summary(english: "Check for the version of the poppler packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"poppler-0.5.4-4.4.el5_3.9", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.5.4-4.4.el5_3.9", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-utils-0.5.4-4.4.el5_3.9", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
