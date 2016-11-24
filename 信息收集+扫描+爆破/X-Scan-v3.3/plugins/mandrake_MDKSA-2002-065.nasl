
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13966);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2002:065: unzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:065 (unzip).");
 script_set_attribute(attribute: "description", value: "A directory traversal vulnerability was discovered in unzip version
5.42 and earlier that allows attackers to overwrite arbitrary files
during extraction of the archive by using a '..' (dot dot) in an
extracted filename, as well as prefixing filenames in the archive with
'/' (slash).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:065");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2001-1268", "CVE-2001-1269");
script_summary(english: "Check for the version of the unzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"unzip-5.50-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"unzip-", release:"MDK7.1")
 || rpm_exists(rpm:"unzip-", release:"MDK7.2")
 || rpm_exists(rpm:"unzip-", release:"MDK8.0")
 || rpm_exists(rpm:"unzip-", release:"MDK8.1")
 || rpm_exists(rpm:"unzip-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2001-1268", value:TRUE);
 set_kb_item(name:"CVE-2001-1269", value:TRUE);
}
exit(0, "Host is not affected");
