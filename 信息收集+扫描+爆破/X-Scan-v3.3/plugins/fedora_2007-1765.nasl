
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1765
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27731);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1765: libvorbis");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1765 (libvorbis)");
 script_set_attribute(attribute: "description", value: "Ogg Vorbis is a fully open, non-proprietary, patent-and royalty-free,
general-purpose compressed audio format for audio and music at fixed
and variable bitrates from 16 to 128 kbps/channel.

The libvorbis package contains runtime libraries for use in programs
that support Ogg Voribs.

-
Update Information:

Multiple security flaws were found in libvorbis.  This updated package fixes th
em all.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");
script_summary(english: "Check for the version of the libvorbis package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libvorbis-1.1.2-3.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
