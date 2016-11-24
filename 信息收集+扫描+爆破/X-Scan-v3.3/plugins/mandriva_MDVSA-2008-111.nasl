
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37236);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:111: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:111 (evolution).");
 script_set_attribute(attribute: "description", value: "Alan Rad Pop of Secunia Research discovered the following two
vulnerabilities in Evolution:
Evolution did not properly validate timezone data when processing
iCalendar attachments. If a user disabled the Itip Formatter plugin
and viewed a crafted iCalendar attachment, an attacker could cause
a denial of service or potentially execute arbitrary code with the
user's privileges (CVE-2008-1108).
Evolution also did not properly validate the DESCRIPTION field when
processing iCalendar attachments. If a user were tricked into
accepting a crafted iCalendar attachment and replied to it from
the calendar window, an attacker could cause a denial of service
or potentially execute arbitrary code with the user's privileges
(CVE-2008-1109).
In addition, Matej Cepl found that Evolution did not properly validate
date fields when processing iCalendar attachments, which could lead to
a denial of service if the user viewed a crafted iCalendar attachment
with the Itip Formatter plugin disabled.
Mandriva Linux has the Itip Formatter plugin enabled by default.
The updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:111");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1108", "CVE-2008-1109");
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

if ( rpm_check( reference:"evolution-2.12.3-1.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.12.3-1.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-mono-2.12.3-1.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.12.3-1.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-2.22.0-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.22.0-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-mono-2.22.0-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.22.0-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"evolution-", release:"MDK2008.0")
 || rpm_exists(rpm:"evolution-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1108", value:TRUE);
 set_kb_item(name:"CVE-2008-1109", value:TRUE);
}
exit(0, "Host is not affected");
