
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38013);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:192: libxml2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:192 (libxml2).");
 script_set_attribute(attribute: "description", value: "A heap-based buffer overflow was found in how libxml2 handled long
XML entity names. If an application linked against libxml2 processed
untrusted malformed XML content, it could cause the application to
crash or possibly execute arbitrary code (CVE-2008-3529).
The updated packages have been patched to prevent this issue.
As well, the patch to fix CVE-2008-3281 has been updated to remove
the hard-coded entity limit that was set to 5M, instead using XML
entity density heuristics. Many thanks to Daniel Veillard of Red Hat
for his hard work in tracking down and dealing with the edge cases
discovered with the initial fix to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:192");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3281", "CVE-2008-3529");
script_summary(english: "Check for the version of the libxml2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxml2-2.6.27-3.4mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.6.27-3.4mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.6.27-3.4mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.6.27-3.4mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2_2-2.6.30-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.6.30-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.6.30-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.6.30-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2_2-2.6.31-1.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.6.31-1.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.6.31-1.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.6.31-1.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libxml2-", release:"MDK2007.1")
 || rpm_exists(rpm:"libxml2-", release:"MDK2008.0")
 || rpm_exists(rpm:"libxml2-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3281", value:TRUE);
 set_kb_item(name:"CVE-2008-3529", value:TRUE);
}
exit(0, "Host is not affected");
