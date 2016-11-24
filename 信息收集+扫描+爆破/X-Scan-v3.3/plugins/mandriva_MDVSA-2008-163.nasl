
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37212);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:163: python");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:163 (python).");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows in the imageop module in Python prior to
2.5.3 allowed context-dependent attackers to cause a denial of service
(crash) or possibly execute arbitrary code via crafted images that
trigger heap-based buffer overflows (CVE-2008-1679). This was due
to an incomplete fix for CVE-2007-4965.
David Remahl of Apple Product Security reported several integer
overflows in a number of core modules (CVE-2008-2315). He also
reported an integer overflow in the hashlib module on Python 2.5 that
lead to unreliable cryptographic digest results (CVE-2008-2316).
Justin Ferguson reported multiple buffer overflows in unicode string
processing that affected 32bit systems (CVE-2008-3142).
Multiple integer overflows were reported by the Google Security Team
that had been fixed in Python 2.5.2 (CVE-2008-3143).
Justin Ferguson reported a number of integer overflows and underflows
in the PyOS_vsnprintf() function, as well as an off-by-one error
when passing zero-length strings, that led to memory corruption
(CVE-2008-3144).
The updated packages have been patched to correct these issues.
As well, Python packages on Mandriva Linux 2007.1 and 2008.0 have
been updated to version 2.5.2. Due to slight packaging changes on
Mandriva Linux 2007.1, a new package is available (tkinter-apps) that
contains binary files (such as /usr/bin/idle) that were previously
in the tkinter package.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:163");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-4965", "CVE-2008-1679", "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
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

if ( rpm_check( reference:"libpython2.5-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-devel-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-base-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-apps-2.5.2-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-devel-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-base-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-apps-2.5.2-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpython2.5-devel-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-base-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-apps-2.5.2-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"python-", release:"MDK2007.1")
 || rpm_exists(rpm:"python-", release:"MDK2008.0")
 || rpm_exists(rpm:"python-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2007-4965", value:TRUE);
 set_kb_item(name:"CVE-2008-1679", value:TRUE);
 set_kb_item(name:"CVE-2008-2315", value:TRUE);
 set_kb_item(name:"CVE-2008-2316", value:TRUE);
 set_kb_item(name:"CVE-2008-3142", value:TRUE);
 set_kb_item(name:"CVE-2008-3143", value:TRUE);
 set_kb_item(name:"CVE-2008-3144", value:TRUE);
}
exit(0, "Host is not affected");
