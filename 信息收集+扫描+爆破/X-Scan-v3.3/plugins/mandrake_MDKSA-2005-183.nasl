
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20430);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:183: wget");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:183 (wget).");
 script_set_attribute(attribute: "description", value: "A vulnerability in libcurl's NTLM function can overflow a stack-based
buffer if given too long a user name or domain name in NTLM
authentication is enabled and either a) pass a user and domain name to
libcurl that together are longer than 192 bytes or b) allow (lib)curl
to follow HTTP redirects and the new URL contains a URL with a user and
domain name that together are longer than 192 bytes.
Wget, as of version 1.10, uses the NTLM code from libcurl and is also
vulnerable to this issue.
The updated packages have been patched to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:183");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3185");
script_summary(english: "Check for the version of the wget package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wget-1.10-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
exit(0, "Host is not affected");
