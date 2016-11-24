
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3456
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32198);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3456: audacity");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3456 (audacity)");
 script_set_attribute(attribute: "description", value: "Audacity is a cross-platform multitrack audio editor. It allows you to
record sounds directly or to import Ogg, WAV, AIFF, AU, IRCAM, or MP3
files. It features a few simple effects, all of the editing features
you should need, and unlimited undo. The GUI was built with wxWindows
and the audio I/O currently uses OSS under Linux. Audacity runs on
Linux/*BSD, MacOS, and Windows.

-
Update Information:

A local attacker could exploit Audacity's insecure handling of the directory fo
r
temporary files to conduct symlink attacks in order to delete arbitrary files
and directories with the privileges of the user running Audacity.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6061");
script_summary(english: "Check for the version of the audacity package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"audacity-1.3.2-21.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
