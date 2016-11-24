
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19898);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:141: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:141 (evolution).");
 script_set_attribute(attribute: "description", value: "Multiple format string vulnerabilities in Evolution 1.5 through 2.3.6.1
allow remote attackers to cause a denial of service (crash) and possibly
execute arbitrary code via (1) full vCard data, (2) contact data from
remote LDAP servers, or (3) task list data from remote servers.
(CVE-2005-2549)
A format string vulnerability in Evolution 1.4 through 2.3.6.1 allows
remote attackers to cause a denial of service (crash) and possibly
execute arbitrary code via the calendar entries such as task lists,
which are not properly handled when the user selects the Calendars tab.
(CVE-2005-2550)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:141");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2549", "CVE-2005-2550");
script_summary(english: "Check for the version of the evolution package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"evolution-2.0.3-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.3-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.0.3-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-2.0.4-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.4-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.0.4-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"evolution-", release:"MDK10.1")
 || rpm_exists(rpm:"evolution-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2549", value:TRUE);
 set_kb_item(name:"CVE-2005-2550", value:TRUE);
}
exit(0, "Host is not affected");
