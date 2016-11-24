
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40762);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:219: kompozer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:219 (kompozer).");
 script_set_attribute(attribute: "description", value: "A vulnerability was found in xmltok_impl.c (expat) that with
specially crafted XML could be exploited and lead to a denial of
service attack. Related to CVE-2009-2625.
Additionally on 2009.0 a patch was added to prevent kompozer from
crashing (#44830), on 2009.1 a format string patch was added to make
it build with the -Wformat -Werror=format-security gcc optimization
switch added in 2009.1
This update fixes these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:219");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2625");
script_summary(english: "Check for the version of the kompozer package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kompozer-0.7.10-3.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kompozer-devel-0.7.10-3.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kompozer-0.7.10-4.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kompozer-devel-0.7.10-4.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kompozer-", release:"MDK2009.0")
 || rpm_exists(rpm:"kompozer-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-2625", value:TRUE);
}
exit(0, "Host is not affected");
