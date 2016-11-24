
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37144);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:168: sound-scripts");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:168 (sound-scripts).");
 script_set_attribute(attribute: "description", value: "The sound initialization scripts provided with Mandriva Linux 2009
activate the Analog Loopback channel when it is present. This channel
is present on most audio chipsets supported by the snd-hda-intel
driver, which are commonly used on recent systems. When active,
this channel plays back the sound received by the line-in and mic-in
channels. If nothing is actually connected to these channels, this
can result in an unpleasant loud noise over the speakers or headphones
connected to the line-out or speaker-out connector.
This update adjusts the sound initialization scripts to mute this
channel by default. Unfortunately, this change will not be applied
automatically on already-installed systems, as existing settings
are automatically stored at shutdown and re-applied at startup on
Mandriva Linux. If you are suffering from this issue, then you can
run the command 'reset_sound' as root after installing this update,
and it should resolve the issue. Alternatively, you can simply disable
/ mute the Analog Loopback channel yourself, using a mixer application.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:168");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the sound-scripts package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sound-scripts-0.56-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sound-scripts-0.56-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
