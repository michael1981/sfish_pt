
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12396);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-176: gnupg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-176");
 script_set_attribute(attribute: "description", value: '
  Updated gnupg packages are now available which correct a bug in the GnuPG
  key validation functions.

  The GNU Privacy Guard (GnuPG) is a utility for encrypting data and
  creating digital signatures.

  When evaluating trust values for the UIDs assigned to a given key,
  GnuPG versions earlier than 1.2.2 would incorrectly associate the trust
  value of the UID having the highest trust value with every UID assigned to
  this key. This would prevent an expected warning message from being
  generated.

  All users are advised to upgrade to these errata packages which include an
  update to GnuPG 1.0.7 containing patches from the GnuPG
  development team to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-176.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0255");
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

if ( rpm_check( reference:"gnupg-1.0.7-7.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
