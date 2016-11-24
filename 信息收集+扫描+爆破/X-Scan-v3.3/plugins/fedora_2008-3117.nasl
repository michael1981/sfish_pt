
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3117
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32382);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 7 2008-3117: libfishsound");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3117 (libfishsound)");
 script_set_attribute(attribute: "description", value: "libfishsound provides a simple programming interface for decoding and
encoding audio data using Xiph.Org codecs (FLAC, Speex and Vorbis).

libfishsound by itself is designed to handle raw codec streams from a
lower level layer such as UDP datagrams. When these codecs are used in
files, they are commonly encapsulated in Ogg to produce Ogg FLAC, Speex
and Ogg Vorbis files.

-
References:

[ 1 ] Bug #441239 - CVE-2008-1686 speex, libfishsound: insufficient boundary
checks
[9]https://bugzilla.redhat.com/show_bug.cgi?id=441239
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1686");
script_summary(english: "Check for the version of the libfishsound package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libfishsound-0.9.1-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
