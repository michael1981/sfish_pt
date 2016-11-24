
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0550
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36929);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-0550: amarok");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0550 (amarok)");
 script_set_attribute(attribute: "description", value: "Amarok is a multimedia player with:
- fresh playlist concept, very fast to use, with drag and drop
- plays all formats supported by the various engines
- audio effects, like reverb and compressor
- compatible with the .m3u and .pls formats for playlists
- nice GUI, integrates into the KDE look, but with a unique touch

-
Update Information:

An update to the latest release, includes new features such as queuing, playlis
t
search and filtering as well as 'stop after current track'. And, long awaited
and finally available: sorting the collection by composer.    Also includes a
security fix concerning the parsing of malformed Audible digital audio files.
For further details, see  [9]http://amarok.kde.org/en/releases/2.0.1.1
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the amarok package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"amarok-2.0.1.1-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
