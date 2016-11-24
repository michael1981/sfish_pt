
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27849);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDKSA-2007:212: pcre");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:212 (pcre).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities were discovered by Tavis Ormandy and
Will Drewry in the way that pcre handled certain malformed regular
expressions. If an application linked against pcre, such as Konqueror,
parses a malicious regular expression, it could lead to the execution
of arbitrary code as the user running the application.
Updated packages have been patched to prevent this issue.
Additionally, Corporate Server 4.0 was updated to pcre version
6.7 which corrected CVE-2006-7225, CVE-2006-7226, CVE-2006-7227,
CVE-2006-7228, and CVE-2006-7230.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:212");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-7225", "CVE-2006-7226", "CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660");
script_summary(english: "Check for the version of the pcre package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpcre0-6.7-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcre0-devel-6.7-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pcre-6.7-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pcre-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-7225", value:TRUE);
 set_kb_item(name:"CVE-2006-7226", value:TRUE);
 set_kb_item(name:"CVE-2006-7227", value:TRUE);
 set_kb_item(name:"CVE-2006-7228", value:TRUE);
 set_kb_item(name:"CVE-2006-7230", value:TRUE);
 set_kb_item(name:"CVE-2007-1659", value:TRUE);
 set_kb_item(name:"CVE-2007-1660", value:TRUE);
}
exit(0, "Host is not affected");
