
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42809);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:297: ffmpeg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:297 (ffmpeg).");
 script_set_attribute(attribute: "description", value: "Vulnerabilities have been discovered and corrected in ffmpeg:
- The ffmpeg lavf demuxer allows user-assisted attackers to cause
a denial of service (application crash) via a crafted GIF file
(CVE-2008-3230)
- FFmpeg 0.4.9, as used by MPlayer, allows context-dependent attackers
to cause a denial of service (memory consumption) via unknown vectors,
aka a Tcp/udp memory leak. (CVE-2008-4869)
- Integer signedness error in the fourxm_read_header function in
libavformat/4xm.c in FFmpeg before revision 16846 allows remote
attackers to execute arbitrary code via a malformed 4X movie file with
a large current_track value, which triggers a NULL pointer dereference
(CVE-2009-0385)
The updated packages fix this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:297");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3230", "CVE-2008-4869", "CVE-2009-0385");
script_summary(english: "Check for the version of the ffmpeg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ffmpeg-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libavformats52-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libavutil49-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libffmpeg51-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libffmpeg-devel-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libffmpeg-static-devel-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libswscaler0-0.4.9-3.pre1.14161.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ffmpeg-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-3230", value:TRUE);
 set_kb_item(name:"CVE-2008-4869", value:TRUE);
 set_kb_item(name:"CVE-2009-0385", value:TRUE);
}
exit(0, "Host is not affected");
