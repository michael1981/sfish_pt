
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18196);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-381: nasm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-381");
 script_set_attribute(attribute: "description", value: '
  An updated nasm package that fixes multiple security issues is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  NASM is an 80x86 assembler.

  Two stack based buffer overflow bugs have been found in nasm. An attacker
  could create an ASM file in such a way that when compiled by a victim,
  could execute arbitrary code on their machine. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the names CAN-2004-1287
  and CAN-2005-1194 to these issues.

  All users of nasm are advised to upgrade to this updated package, which
  contains backported fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-381.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1287", "CVE-2005-1194");
script_summary(english: "Check for the version of the nasm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nasm-0.98-8.EL21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98-8.EL21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98-8.EL21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.35-3.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.38-3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.38-3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.38-3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
