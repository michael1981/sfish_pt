
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18305);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:089: cdrdao");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:089 (cdrdao).");
 script_set_attribute(attribute: "description", value: "The cdrdao package contains two vulnerabilities; the first allows local
users to read arbitrary files via the show-data command and the second
allows local users to overwrite arbitrary files via a symlink attack on
the ~/.cdrdao configuration file. This can also lead to elevated
privileges (a root shell) due to cdrdao being installed suid root.
The provided packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:089");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0137", "CVE-2002-0138");
script_summary(english: "Check for the version of the cdrdao package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cdrdao-1.1.8-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cdrdao-gcdmaster-1.1.8-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cdrdao-1.1.9-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cdrdao-gcdmaster-1.1.9-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cdrdao-1.1.9-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cdrdao-gcdmaster-1.1.9-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cdrdao-", release:"MDK10.0")
 || rpm_exists(rpm:"cdrdao-", release:"MDK10.1")
 || rpm_exists(rpm:"cdrdao-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2002-0137", value:TRUE);
 set_kb_item(name:"CVE-2002-0138", value:TRUE);
}
exit(0, "Host is not affected");
