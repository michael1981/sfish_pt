
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20446);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:214: gdk-pixbuf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:214 (gdk-pixbuf).");
 script_set_attribute(attribute: "description", value: "A heap overflow vulnerability in the GTK+ gdk-pixbuf XPM image
rendering library could allow for arbitrary code execution. This allows
an attacker to provide a carefully crafted XPM image which could
possibly allow for arbitrary code execution in the context of the user
viewing the image. (CVE-2005-3186)
Ludwig Nussel discovered an integer overflow bug in the way gdk-pixbuf
processes XPM images. An attacker could create a carefully crafted XPM
file in such a way that it could cause an application linked with
gdk-pixbuf to execute arbitrary code or crash when the file was opened
by a victim. (CVE-2005-2976)
Ludwig Nussel also discovered an infinite-loop denial of service bug
in the way gdk-pixbuf processes XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause an
application linked with gdk-pixbuf to stop responding when the file was
opened by a victim. (CVE-2005-2975)
The gtk+2.0 library also contains the same gdk-pixbuf code with the
same vulnerability.
The Corporate Server 2.1 packages have additional patches to address
CVE-2004-0782,0783,0788 (additional XPM/ICO image issues),
CVE-2004-0753 (BMP image issues) and CVE-2005-0891 (additional BMP
issues). These were overlooked on this platform with earlier updates.
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:214");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788", "CVE-2005-0891", "CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
script_summary(english: "Check for the version of the gdk-pixbuf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gdk-pixbuf-", release:"MDK10.2")
 || rpm_exists(rpm:"gdk-pixbuf-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-0753", value:TRUE);
 set_kb_item(name:"CVE-2004-0782", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
exit(0, "Host is not affected");
