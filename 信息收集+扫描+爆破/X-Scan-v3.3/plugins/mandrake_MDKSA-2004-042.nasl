
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14141);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:042: rsync");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:042 (rsync).");
 script_set_attribute(attribute: "description", value: "Rsync before 2.6.1 does not properly sanitize paths when running a
read/write daemon without using chroot, allows remote attackers to write
files outside of the module's path.
The updated packages provide a patched rsync to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:042");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0426");
script_summary(english: "Check for the version of the rsync package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rsync-2.6.0-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"MDK10.0")
 || rpm_exists(rpm:"rsync-", release:"MDK9.1")
 || rpm_exists(rpm:"rsync-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0426", value:TRUE);
}
exit(0, "Host is not affected");
