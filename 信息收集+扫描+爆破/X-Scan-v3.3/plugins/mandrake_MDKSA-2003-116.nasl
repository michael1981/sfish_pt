
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14098);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:116: lftp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:116 (lftp).");
 script_set_attribute(attribute: "description", value: "A buffer overflow vulnerability was discovered by Ulf Harnhammar in
the lftp FTP client when connecting to a web server using HTTP or
HTTPS and using the 'ls' or 'rels' command on specially prepared
directory. This vulnerability exists in lftp versions 2.3.0 through
2.6.9 and is corrected upstream in 2.6.10.
The updated packages are patched to protect against this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:116");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0963");
script_summary(english: "Check for the version of the lftp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lftp-2.6.0-1.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.4-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.6-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"lftp-", release:"MDK9.0")
 || rpm_exists(rpm:"lftp-", release:"MDK9.1")
 || rpm_exists(rpm:"lftp-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0963", value:TRUE);
}
exit(0, "Host is not affected");
