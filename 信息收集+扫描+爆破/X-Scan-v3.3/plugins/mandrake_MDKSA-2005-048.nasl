
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17277);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:048: curl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:048 (curl).");
 script_set_attribute(attribute: "description", value: "'infamous41md' discovered a buffer overflow vulnerability in
libcurl's NTLM authorization base64 decoding. This could allow a
remote attacker using a prepared remote server to execute arbitrary
code as the user running curl.
The updated packages are patched to deal with these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:048");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0490");
script_summary(english: "Check for the version of the curl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"curl-7.11.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcurl2-7.11.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcurl2-devel-7.11.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.12.1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.12.1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"curl-", release:"MDK10.0")
 || rpm_exists(rpm:"curl-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0490", value:TRUE);
}
exit(0, "Host is not affected");
