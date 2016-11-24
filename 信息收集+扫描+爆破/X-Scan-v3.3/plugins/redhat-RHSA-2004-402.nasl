
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14213);
 script_version ("$Revision: 1.12 $");
 script_name(english: "RHSA-2004-402: libpng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-402");
 script_set_attribute(attribute: "description", value: '
  Updated libpng packages that fix several issues are now available.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  During a source code audit, Chris Evans discovered several buffer overflows
  in libpng. An attacker could create a carefully crafted PNG file in such a
  way that it would cause an application linked with libpng to execute
  arbitrary code when the file was opened by a victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0597 to these issues.

  In addition, this audit discovered a potential NULL pointer dereference in
  libpng (CAN-2004-0598) and several integer overflow issues (CAN-2004-0599).
  An attacker could create a carefully crafted PNG file in such a way that
  it would cause an application linked with libpng to crash when the file was
  opened by the victim.

  Red Hat would like to thank Chris Evans for discovering these issues.

  For users of Red Hat Enterprise Linux 2.1 these patches also include a more
  complete fix for the out of bounds memory access flaw (CAN-2002-1363).

  All users are advised to update to the updated libpng packages which
  contain backported security patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-402.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1363", "CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
script_summary(english: "Check for the version of the libpng packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpng-1.0.14-7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.14-7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-25", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.2-25", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.13-15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.13-15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
