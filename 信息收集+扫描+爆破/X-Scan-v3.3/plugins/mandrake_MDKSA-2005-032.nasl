
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16375);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2005:032-1: cpio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:032-1 (cpio).");
 script_set_attribute(attribute: "description", value: "A vulnerability in cpio was discovered where cpio would create world-
writeable files when used in -o/--create mode and giving an output
file (with -O). This would allow any user to modify the created cpio
archive. The updated packages have been patched so that cpio now
respects the current umask setting of the user.
Update:
The updated cpio packages for 10.1, while they would install with
urpmi on the commandline, would not install via rpmdrake. The updated
packages correct that.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:032-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-1999-1572");
script_summary(english: "Check for the version of the cpio package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cpio-2.5-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cpio-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-1999-1572", value:TRUE);
}
exit(0, "Host is not affected");
