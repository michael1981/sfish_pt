
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24560);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:174: gstreamer-ffmpeg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:174 (gstreamer-ffmpeg).");
 script_set_attribute(attribute: "description", value: "Gstreamer-ffmpeg uses an embedded copy of ffmpeg and as such has been
updated to address the following issue: Multiple buffer overflows in
libavcodec in ffmpeg before 0.4.9_p20060530 allow remote attackers to
cause a denial of service or possibly execute arbitrary code via
multiple unspecified vectors in (1) dtsdec.c, (2) vorbis.c, (3) rm.c,
(4)sierravmd.c, (5) smacker.c, (6) tta.c, (7) 4xm.c, (8) alac.c, (9)
cook.c, (10)shorten.c, (11) smacker.c, (12) snow.c, and (13) tta.c.
NOTE: it is likely that this is a different vulnerability than
CVE-2005-4048 and CVE-2006-2802.
Updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:174");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-4048", "CVE-2006-4800");
script_summary(english: "Check for the version of the gstreamer-ffmpeg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gstreamer-ffmpeg-0.8.6-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-ffmpeg-0.8.7-3.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gstreamer-ffmpeg-", release:"MDK2006.0")
 || rpm_exists(rpm:"gstreamer-ffmpeg-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2005-4048", value:TRUE);
 set_kb_item(name:"CVE-2006-4800", value:TRUE);
}
exit(0, "Host is not affected");
