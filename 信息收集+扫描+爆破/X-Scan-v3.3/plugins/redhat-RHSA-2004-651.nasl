
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15947);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-651: imlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-651");
 script_set_attribute(attribute: "description", value: '
  Updated imlib packages that fix several integer and buffer overflows are
  now available.

  [Updated Dec 22, 2004]
  Added multilib packages to the Itanium, PPC, AMD64/Intel EM64T, and IBM
  eServer zSeries architectures for Red Hat Enterprise Linux version 3.

  The imlib packages contain an image loading and rendering library.

  Pavel Kankovsky discovered several heap overflow flaws that were found in
  the imlib image handler. An attacker could create a carefully crafted image
  file in such a way that it could cause an application linked with imlib to
  execute arbitrary code when the file was opened by a victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1025 to this issue.

  Additionally, Pavel discovered several integer overflow flaws that were
  found in the imlib image handler. An attacker could create a carefully
  crafted image file in such a way that it could cause an application linked
  with imlib to execute arbitrary code or crash when the file was opened by a
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-1026 to this issue.

  Users of imlib should update to these updated packages, which contain
  backported patches and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-651.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1025", "CVE-2004-1026");
script_summary(english: "Check for the version of the imlib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"imlib-1.9.13-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-13.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-13.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
