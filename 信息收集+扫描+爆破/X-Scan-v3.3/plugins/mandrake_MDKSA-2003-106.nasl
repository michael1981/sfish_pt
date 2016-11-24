
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14088);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:106: fileutils/coreutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:106 (fileutils/coreutils).");
 script_set_attribute(attribute: "description", value: "A memory starvation denial of service vulnerability in the ls program
was discovered by Georgi Guninski. It is possible to allocate a huge
amount of memory by specifying certain command-line arguments. It is
also possible to exploit this remotely via programs that call ls such
as wu-ftpd (although wu-ftpd is no longer shipped with Mandrake Linux).
Likewise, a non-exploitable integer overflow problem was discovered in
ls, which can be used to crash ls by specifying certain command-line
arguments. This can also be triggered via remotely accessible services
such as wu-ftpd.
The provided packages include a patched ls to fix these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:106");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0853", "CVE-2003-0854");
script_summary(english: "Check for the version of the fileutils/coreutils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fileutils-4.1.11-6.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"coreutils-4.5.7-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"coreutils-doc-4.5.7-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"coreutils-5.0-6.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"coreutils-doc-5.0-6.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"fileutils-", release:"MDK9.0")
 || rpm_exists(rpm:"fileutils-", release:"MDK9.1")
 || rpm_exists(rpm:"fileutils-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0853", value:TRUE);
 set_kb_item(name:"CVE-2003-0854", value:TRUE);
}
exit(0, "Host is not affected");
