
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36693);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:003: python");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:003 (python).");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows in imageop.c in the imageop module in
Python 1.5.2 through 2.5.1 allow context-dependent attackers to
break out of the Python VM and execute arbitrary code via large
integer values in certain arguments to the crop function, leading to
a buffer overflow, a different vulnerability than CVE-2007-4965 and
CVE-2008-1679. (CVE-2008-4864)
Multiple integer overflows in Python 2.2.3 through 2.5.1, and 2.6,
allow context-dependent attackers to have an unknown impact via
a large integer value in the tabsize argument to the expandtabs
method, as implemented by (1) the string_expandtabs function in
Objects/stringobject.c and (2) the unicode_expandtabs function in
Objects/unicodeobject.c. NOTE: this vulnerability reportedly exists
because of an incomplete fix for CVE-2008-2315. (CVE-2008-5031)
The updated Python packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:003");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-4965", "CVE-2008-1679", "CVE-2008-2315", "CVE-2008-4864", "CVE-2008-5031");
script_summary(english: "Check for the version of the python package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpython2.5-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-devel-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-base-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-apps-2.5.2-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-devel-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-base-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-apps-2.5.2-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-devel-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-base-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-apps-2.5.2-5.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"python-", release:"MDK2008.0")
 || rpm_exists(rpm:"python-", release:"MDK2008.1")
 || rpm_exists(rpm:"python-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2007-4965", value:TRUE);
 set_kb_item(name:"CVE-2008-1679", value:TRUE);
 set_kb_item(name:"CVE-2008-2315", value:TRUE);
 set_kb_item(name:"CVE-2008-4864", value:TRUE);
 set_kb_item(name:"CVE-2008-5031", value:TRUE);
}
exit(0, "Host is not affected");
