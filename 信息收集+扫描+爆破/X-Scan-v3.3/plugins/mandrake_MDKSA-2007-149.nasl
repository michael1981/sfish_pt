
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25795);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:149: bind");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:149 (bind).");
 script_set_attribute(attribute: "description", value: "The DNS query id generation code in BIND9 is vulnerable to
cryptographic analysis which provides a 1-in-8 change of guessing the
next query ID for 50% of the query IDs, which could be used by a remote
attacker to perform cache poisoning by an attacker (CVE-2007-2926).
As well, in BIND9 9.4.x, the default ACLs were note being correctly
set, which could allow anyone to make recursive queries and/or query
the cache contents (CVE-2007-2925).
This update provides packages which are patched to prevent these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:149");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-2925", "CVE-2007-2926");
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

if ( rpm_check( reference:"bind-9.3.2-8.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.3.2-8.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.2-8.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-9.4.1-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.4.1-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.4.1-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"bind-", release:"MDK2007.0")
 || rpm_exists(rpm:"bind-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-2925", value:TRUE);
 set_kb_item(name:"CVE-2007-2926", value:TRUE);
}
exit(0, "Host is not affected");
