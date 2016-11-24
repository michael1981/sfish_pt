
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24945);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:079-1: xorg-x11");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:079-1 (xorg-x11).");
 script_set_attribute(attribute: "description", value: "Local exploitation of a memory corruption vulnerability in the X.Org
and XFree86 X server could allow an attacker to execute arbitrary
code with privileges of the X server, typically root.
The vulnerability exists in the ProcXCMiscGetXIDList() function in the
XC-MISC extension. This request is used to determine what resource IDs
are available for use. This function contains two vulnerabilities,
both result in memory corruption of either the stack or heap. The
ALLOCATE_LOCAL() macro used by this function allocates memory on the
stack using alloca() on systems where alloca() is present, or using
the heap otherwise. The handler function takes a user provided value,
multiplies it, and then passes it to the above macro. This results in
both an integer overflow vulnerability, and an alloca() stack pointer
shifting vulnerability. Both can be exploited to execute arbitrary
code. (CVE-2007-1003)
iDefense reported two integer overflows in the way X.org handled
various font files. A malicious local user could exploit these issues
to potentially execute arbitrary code with the privileges of the
X.org server. (CVE-2007-1351, CVE-2007-1352)
Multiple integer overflows in (1) the XGetPixel function in ImUtil.c
in x.org libx11 before 1.0.3, and (2) XInitImage function in xwd.c for
ImageMagick, allow user-assisted remote attackers to cause a denial
of service (crash) or information leak via crafted images with large
or negative values that trigger a buffer overflow. (CVE-2007-1667)
Updated packages are patched to address these issues.
Update:
Packages for Mandriva Linux 2007.1 are now available.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:079-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667");
script_summary(english: "Check for the version of the xorg-x11 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libx11-common-1.1.1-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libx11_6-1.1.1-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libx11_6-devel-1.1.1-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libx11_6-static-devel-1.1.1-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxfont1-1.2.7-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxfont1-devel-1.2.7-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxfont1-static-devel-1.2.7-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-common-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-devel-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xati-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xchips-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xdmx-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xephyr-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xepson-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xfake-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xfbdev-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xgl-0.0.1-0.20070105.4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xi810-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xmach64-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xmga-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xneomagic-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xnest-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xnvidia-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xorg-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xpm2-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xprt-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xr128-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xsdl-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xsmi-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xvesa-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xvfb-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xvia-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xvnc-1.2.0-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xorg-x11-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1003", value:TRUE);
 set_kb_item(name:"CVE-2007-1351", value:TRUE);
 set_kb_item(name:"CVE-2007-1352", value:TRUE);
 set_kb_item(name:"CVE-2007-1667", value:TRUE);
}
exit(0, "Host is not affected");
