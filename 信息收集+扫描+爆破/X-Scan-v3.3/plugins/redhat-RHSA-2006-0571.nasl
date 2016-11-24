
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22069);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0571: gnupg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0571");
 script_set_attribute(attribute: "description", value: '
  An updated GnuPG package that fixes a security issue is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GnuPG is a utility for encrypting data and creating digital signatures.

  An integer overflow flaw was found in GnuPG. An attacker could create a
  carefully crafted message packet with a large length that could cause GnuPG
  to crash or possibly overwrite memory when opened. (CVE-2006-3082)

  All users of GnuPG are advised to upgrade to this updated package, which
  contains a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0571.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3082");
script_summary(english: "Check for the version of the gnupg packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnupg-1.0.7-17", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.1-16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.6-5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
