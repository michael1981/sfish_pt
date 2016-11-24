
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17680);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-354: tetex");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-354");
 script_set_attribute(attribute: "description", value: '
  Updated tetex packages that fix several integer overflows are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  TeTeX is an implementation of TeX for Linux or UNIX systems. TeX takes
  a text file and a set of formatting commands as input and creates a
  typesetter-independent .dvi (DeVice Independent) file as output.

  A number of security flaws have been found affecting libraries used
  internally within teTeX. An attacker who has the ability to trick a user
  into processing a malicious file with teTeX could cause teTeX to crash or
  possibly execute arbitrary code.

  A number of integer overflow bugs that affect Xpdf were discovered. The
  teTeX package contains a copy of the Xpdf code used for parsing PDF files
  and is therefore affected by these bugs. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CAN-2004-0888 and
  CAN-2004-1125 to these issues.

  A number of integer overflow bugs that affect libtiff were discovered. The
  teTeX package contains an internal copy of libtiff used for parsing TIFF
  image files and is therefore affected by these bugs. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CAN-2004-0803, CAN-2004-0804 and CAN-2004-0886 to these issues.

  Also latex2html is added to package tetex-latex for 64bit platforms.

  Users of teTeX should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-354.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-0888", "CVE-2004-1125");
script_summary(english: "Check for the version of the tetex packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tetex-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-38.5E.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-1.0.7-67.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-67.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-67.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-67.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-67.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-67.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
