
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36999);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:182-1: wordnet");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:182-1 (wordnet).");
 script_set_attribute(attribute: "description", value: "Rob Holland found several programming errors in WordNet which could
lead to the execution or arbitrary code when used with untrusted input
(CVE-2008-2149, CVE-2008-3908).
Update:
The previous patch had a typo that caused incorrect behaviour in
WordNet. This update uses an update patch that corrects the issue
and also notes the additional assigned CVE name for these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:182-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2149", "CVE-2008-3908");
script_summary(english: "Check for the version of the wordnet package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libwordnet3.0-3.0-6.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwordnet3.0-devel-3.0-6.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wordnet-3.0-6.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwordnet3.0-3.0-6.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwordnet3.0-devel-3.0-6.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wordnet-3.0-6.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wordnet-", release:"MDK2008.0")
 || rpm_exists(rpm:"wordnet-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-2149", value:TRUE);
 set_kb_item(name:"CVE-2008-3908", value:TRUE);
}
exit(0, "Host is not affected");
