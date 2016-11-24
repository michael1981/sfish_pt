
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19885);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2005:124: zlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:124 (zlib).");
 script_set_attribute(attribute: "description", value: "A previous zlib update (MDKSA-2005:112; CVE-2005-2096) fixed an overflow
flaw in the zlib program. While that update did indeed fix the reported
overflow issue, Markus Oberhumber discovered additional ways that a
specially-crafted compressed stream could trigger an overflow. An
attacker could create such a stream that would cause a linked
application to crash if opened by a user.
The updated packages are provided to protect against this flaw. The
Corporate Server 2.1 product is not affected by this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:124");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1849");
script_summary(english: "Check for the version of the zlib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zlib1-1.2.1-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.2.1.1-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1.1-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.2.2.2-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.2.2-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK10.0")
 || rpm_exists(rpm:"zlib-", release:"MDK10.1")
 || rpm_exists(rpm:"zlib-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
}
exit(0, "Host is not affected");
