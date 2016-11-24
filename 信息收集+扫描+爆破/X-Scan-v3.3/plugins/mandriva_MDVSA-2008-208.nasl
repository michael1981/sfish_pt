
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37569);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:208-1: pam_mount");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:208-1 (pam_mount).");
 script_set_attribute(attribute: "description", value: "pam_mount 0.10 through 0.45, when luserconf is enabled, does not verify
mountpoint and source ownership before mounting a user-defined volume,
which allows local users to bypass intended access restrictions via
a local mount.
The updated packages have been patched to fix the issue.
Update:
The fix for CVE-2008-3970 uncovered crashes in the code handling the
'allow', 'deny', and 'require' options in pam_mount-0.33, released
for Mandriva Linux 2008 Spring. Also, the verification of the allowed
mount options ('allow' configuration directive) was inverted in
pam_mount-0.33.
This update fixes these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:208-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3970");
script_summary(english: "Check for the version of the pam_mount package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pam_mount-0.33-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pam_mount-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3970", value:TRUE);
}
exit(0, "Host is not affected");
