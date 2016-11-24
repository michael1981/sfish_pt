
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18476);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-506: mikmod");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-506");
 script_set_attribute(attribute: "description", value: '
  Updated mikmod packages that fix a security issue are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  MikMod is a well known MOD music file player for UNIX-based systems.

  A buffer overflow bug was found in mikmod during the processing of archive
  filenames. An attacker could create a malicious archive that when opened by
  mikmod could result in arbitrary code execution. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2003-0427
  to this issue.

  Users of mikmod are advised to upgrade to these erratum packages, which
  contain backported security patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-506.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0427");
script_summary(english: "Check for the version of the mikmod packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mikmod-3.1.6-14.EL21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mikmod-3.1.6-22.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mikmod-devel-3.1.6-22.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mikmod-3.1.6-32.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mikmod-devel-3.1.6-32.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
