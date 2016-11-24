
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20360);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-843: netpbm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-843");
 script_set_attribute(attribute: "description", value: '
  Updated netpbm packages that fix two security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The netpbm package contains a library of functions that support programs
  for handling various graphics file formats.

  A stack based buffer overflow bug was found in the way netpbm converts
  Portable Anymap (PNM) files into Portable Network Graphics (PNG). A
  specially crafted PNM file could allow an attacker to execute arbitrary
  code by attempting to convert a PNM file to a PNG file when using pnmtopng
  with the \'-text\' option. The Common Vulnerabilities and Exposures project
  has assigned the name CVE-2005-3632 to this issue.

  An "off by one" bug was found in the way netpbm converts Portable Anymap
  (PNM) files into Portable Network Graphics (PNG). If a victim attempts to
  convert a specially crafted 256 color PNM file to a PNG file, then it can
  cause the pnmtopng utility to crash. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2005-3662 to this issue.

  All users of netpbm should upgrade to these updated packages, which contain
  backported patches that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-843.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3632", "CVE-2005-3662");
script_summary(english: "Check for the version of the netpbm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"netpbm-9.24-9.AS21.6", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-9.AS21.6", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-9.AS21.6", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-11.30.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-11.30.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-11.30.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
