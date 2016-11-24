
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15629);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-577: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-577");
 script_set_attribute(attribute: "description", value: '
  Updated libtiff packages that fix various buffer and integer overflows are
  now available.

  The libtiff package contains a library of functions for manipulating TIFF
  (Tagged Image File Format) image format files. TIFF is a widely used file
  format for bitmapped images.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect libtiff. An attacker who has the ability to trick
  a user into opening a malicious TIFF file could cause the application
  linked to libtiff to crash or possibly execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CAN-2004-0886 and CAN-2004-0804 to these issues.

  Additionally, a number of buffer overflow bugs that affect libtiff have
  been found. An attacker who has the ability to trick a user into opening a
  malicious TIFF file could cause the application linked to libtiff to crash
  or possibly execute arbitrary code. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0803 to
  this issue.

  All users are advised to upgrade to these errata packages, which contain
  fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-577.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-1307");
script_summary(english: "Check for the version of the libtiff packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libtiff-3.5.5-17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.5-17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-20.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-20.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
