
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36436);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:079: sarg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:079 (sarg).");
 script_set_attribute(attribute: "description", value: "A stack-based buffer overflow in sarg (Squid Analysis Report Generator)
allowed remote attackers to execute arbitrary code via a long Squid
proxy server User-Agent header (CVE-2008-1167).
A cross-site scripting vulnerability in sarg version 2.x prior to
2.2.5 allowed remote attackers to inject arbitrary web script or
HTML via the User-Agent heder, which is not properly handled when
displaying the Squid proxy log (CVE-2008-1168).
In addition, a number of other fixes have been made such as making
the getword() function more robust which should prevent any overflows,
other segfaults have been fixed, and the useragent report is now more
consistent with the other reports.
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:079");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1167", "CVE-2008-1168");
script_summary(english: "Check for the version of the sarg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sarg-2.2.5-0.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sarg-2.2.5-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sarg-2.2.5-0.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sarg-", release:"MDK2007.0")
 || rpm_exists(rpm:"sarg-", release:"MDK2007.1")
 || rpm_exists(rpm:"sarg-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2008-1167", value:TRUE);
 set_kb_item(name:"CVE-2008-1168", value:TRUE);
}
exit(0, "Host is not affected");
