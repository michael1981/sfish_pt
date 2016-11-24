
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24592);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:207: bind");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:207 (bind).");
 script_set_attribute(attribute: "description", value: "The BIND DNS server is vulnerable to the recently-discovered OpenSSL
RSA signature verification problem (CVE-2006-4339). BIND uses RSA
cryptography as part of its DNSSEC implementation. As a result, to
resolve the security issue, these packages need to be upgraded and for
both KEY and DNSKEY record types, new RSASHA1 and RSAMD5 keys need to
be generated using the '-e' option of dnssec-keygen, if the current
keys were generated using the default exponent of 3.
You are able to determine if your keys are vulnerable by looking at the
algorithm (1 or 5) and the first three characters of the Base64 encoded
RSA key. RSAMD5 (1) and RSASHA1 (5) keys that start with 'AQM', 'AQN',
'AQO', or 'AQP' are vulnerable.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:207");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4339");
script_summary(english: "Check for the version of the bind package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bind-9.3.1-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.3.1-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.1-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-9.3.2-8.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.3.2-8.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.2-8.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"bind-", release:"MDK2006.0")
 || rpm_exists(rpm:"bind-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4339", value:TRUE);
}
exit(0, "Host is not affected");
