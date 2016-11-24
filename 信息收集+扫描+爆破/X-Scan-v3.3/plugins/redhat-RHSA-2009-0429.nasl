
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36179);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0429: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0429");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX® Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems.

  Multiple integer overflow flaws were found in the CUPS JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause CUPS to crash
  or, potentially, execute arbitrary code as the "lp" user if the file was
  printed. (CVE-2009-0147, CVE-2009-1179)

  Multiple buffer overflow flaws were found in the CUPS JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause CUPS to crash
  or, potentially, execute arbitrary code as the "lp" user if the file was
  printed. (CVE-2009-0146, CVE-2009-1182)

  Multiple flaws were found in the CUPS JBIG2 decoder that could lead to the
  freeing of arbitrary memory. An attacker could create a malicious PDF file
  that would cause CUPS to crash or, potentially, execute arbitrary code
  as the "lp" user if the file was printed. (CVE-2009-0166, CVE-2009-1180)

  Multiple input validation flaws were found in the CUPS JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause CUPS to crash
  or, potentially, execute arbitrary code as the "lp" user if the file was
  printed. (CVE-2009-0800)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  discovered in the Tagged Image File Format (TIFF) decoding routines used by
  the CUPS image-converting filters, "imagetops" and "imagetoraster". An
  attacker could create a malicious TIFF file that could, potentially,
  execute arbitrary code as the "lp" user if the file was printed.
  (CVE-2009-0163)

  Multiple denial of service flaws were found in the CUPS JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause CUPS to crash
  when printed. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

  Red Hat would like to thank Aaron Sigel, Braden Thomas and Drew Yao of
  the Apple Product Security team, and Will Dormann of the CERT/CC for
  responsibly reporting these flaws.

  Users of cups are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing the
  update, the cupsd daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0429.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.3.7-8.el5_3.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.3.7-8.el5_3.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.3.7-8.el5_3.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-lpd-1.3.7-8.el5_3.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.27.el4_7.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
