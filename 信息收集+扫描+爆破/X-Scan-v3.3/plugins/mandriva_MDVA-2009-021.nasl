
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37044);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2009:021: drakxtools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2009:021 (drakxtools).");
 script_set_attribute(attribute: "description", value: "This update fixes several minor issues with drakxtools:
- it prevents the harddrake service to uselessly backup xorg.conf
when not configuring the driver
- it fixes a couple minor issues with diskdrake:
o stop crashing when udev & diskdrake are competing in order to
create a device node (#41832)
o --dav: handle davfs2 credentials in /etc/davfs2/secrets (#44190)
o --dav: handle https
o --nfs: handle host:/ (#44320)
o --smb: cifs must be used instead of smbfs (#42483)
o lookup for Samba master browsers too
- it fixes displaying various devices in their proper category in
the harddrake GUI
- it handle a couple of new network driver
- finish-install:
o show only installed 3D desktops
o adapt to new Xconfig::glx API (drak3d 1.21)
o use /dev/urandom instead of /dev/random to generate salt for
passwords (since reading on /dev/random can block boot process)
- prevent mdkapplet from crashing (#46477)
- smb: fix netbios name resolution (#42483, thanks to Derek Jennings)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2009:021");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the drakxtools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"drakx-finish-install-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-backend-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-curses-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-http-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"harddrake-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"harddrake-ui-11.71.7-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
