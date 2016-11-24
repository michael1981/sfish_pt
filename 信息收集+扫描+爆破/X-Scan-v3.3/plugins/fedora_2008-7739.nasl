
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7739
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34148);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-7739: amarok");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7739 (amarok)");
 script_set_attribute(attribute: "description", value: "Amarok is a multimedia player with:
- fresh playlist concept, very fast to use, with drag and drop
- plays all formats supported by the various engines
- audio effects, like reverb and compressor
- compatible with the .m3u and .pls formats for playlists
- nice GUI, integrates into the KDE look, but with a unique touch


Amarok can use various engines to decode sound : helix and xine.
To use the helix engine, you need to install either HelixPlayer
or RealPlayer

-
Update Information:

Amarok 1.4.10 has been released to fix a security problem.  For more informatio
n
please see [9]http://amarok.kde.org/en/node/535/  Please update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3699");
script_summary(english: "Check for the version of the amarok package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"amarok-1.4.10-1.fc9", release:"FC9") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
