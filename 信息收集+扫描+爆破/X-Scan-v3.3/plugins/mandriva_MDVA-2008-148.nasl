
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37523);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:148: pulseaudio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:148 (pulseaudio).");
 script_set_attribute(attribute: "description", value: "Some issues relating to thread cancellation have been discovered in
the pulseaudio package shipped with Mandriva Linux 2009.0.
These issues could result in the crash of an application acting as
a pulseaudio client. This condition is greatly exacerbated when
the client is unable to connect to the pulseaudio server. Due to
the fact that libcanberra is used to play event sounds in GTK apps,
this problem could present itself when running GTK applications as
root which, under some circumstances, was unable to connect to the
user's pulseaudio daemon.
The problems were traced to the use of libasycns in pulseaudio and
this updated package is compiled without support for this library
(it is not essential to pulseaudio operation).
In addition, the version of pulseaudio shipped in Mandriva Linux
2009.0 used wallclock time to determine when a misbehaving daemon
was overloading the CPU (under which circumstances the daemon
terminated). This can cause problems when the time is changed manually
or when daylight savings kick in. This package also contains an
upstream fix to use monotonic time which does not suffer from this
limitation.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:148");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the pulseaudio package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpulseaudio0-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpulseaudio-devel-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpulsecore5-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpulseglib20-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpulsezeroconf0-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-esound-compat-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-module-bluetooth-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-module-gconf-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-module-jack-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-module-lirc-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-module-x11-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-module-zeroconf-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pulseaudio-utils-0.9.10-11.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
