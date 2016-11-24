
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3898
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32339);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3898: libvorbis");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3898 (libvorbis)");
 script_set_attribute(attribute: "description", value: "Ogg Vorbis is a fully open, non-proprietary, patent-and royalty-free,
general-purpose compressed audio format for audio and music at fixed
and variable bitrates from 16 to 128 kbps/channel.

The libvorbis package contains runtime libraries for use in programs
that support Ogg Voribs.

-
Update Information:

Will Drewry of the Google Security Team reported several flaws in the way
libvorbis processed audio data. An attacker could create a carefully  crafted
OGG audio file in such a way that it could cause an application  linked with
libvorbis to crash, or execute arbitrary code when it was  opened.
(CVE-2008-1419, CVE-2008-1420, CVE-2008-1423)    Moreover, additional OGG file
sanity-checks have been added to prevent  possible exploitation of similar
issues in the future.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");
script_summary(english: "Check for the version of the libvorbis package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libvorbis-1.1.2-4.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
