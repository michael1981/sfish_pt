
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24652);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:039: gtk+2.0");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:039 (gtk+2.0).");
 script_set_attribute(attribute: "description", value: "The GdkPixbufLoader function in GIMP ToolKit (GTK+) in GTK 2 (gtk2)
allows context-dependent attackers to cause a denial of service (crash)
via a malformed image file. (CVE-2007-0010)
The version of libgtk+2.0 shipped with Mandriva Linux 2007 fails
various portions of the lsb-test-desktop test suite, part of LSB 3.1
certification testing.
The updated packages also address the following issues:
The Home and Desktop entries in the GTK File Chooser are not always
visible (#26644).
GTK+-based applications (which includes all the Mandriva Linux
configuration tools, for example) crash (instead of falling back to the
default theme) when an invalid icon theme is selected. (#27013)
Additional patches from GNOME CVS have been included to address the
following issues from the GNOME bugzilla:
* 357132 - fix RGBA colormap issue
* 359537,357280,359052 - fix various printer bugs
* 357566,353736,357050,363437,379503 - fix various crashes
* 372527 - fix fileselector bug +
potential deadlock
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:039");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0010");
script_summary(english: "Check for the version of the gtk+2.0 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gtk+2.0-2.10.3-5.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.10.3-5.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.10.3-5.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.10.3-5.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.10.3-5.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.10.3-5.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gtk+2.0-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-0010", value:TRUE);
}
exit(0, "Host is not affected");
