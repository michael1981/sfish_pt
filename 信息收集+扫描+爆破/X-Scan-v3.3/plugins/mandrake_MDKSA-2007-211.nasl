
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37237);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDKSA-2007:211: pcre");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:211 (pcre).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities were discovered by Tavis Ormandy and
Will Drewry in the way that pcre handled certain malformed regular
expressions. If an application linked against pcre, such as Konqueror,
parses a malicious regular expression, it could lead to the execution
of arbitrary code as the user running the application.
Updated packages have been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:211");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
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

if ( rpm_check( reference:"libpcre-devel-7.3-0.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcre0-7.3-0.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pcre-7.3-0.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pcre-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2006-7230", value:TRUE);
 set_kb_item(name:"CVE-2007-1659", value:TRUE);
 set_kb_item(name:"CVE-2007-1660", value:TRUE);
 set_kb_item(name:"CVE-2007-1661", value:TRUE);
 set_kb_item(name:"CVE-2007-1662", value:TRUE);
 set_kb_item(name:"CVE-2007-4766", value:TRUE);
 set_kb_item(name:"CVE-2007-4767", value:TRUE);
 set_kb_item(name:"CVE-2007-4768", value:TRUE);
}
exit(0, "Host is not affected");
