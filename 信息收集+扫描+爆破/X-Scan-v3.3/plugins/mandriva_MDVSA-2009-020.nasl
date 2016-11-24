
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36846);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:020: xine-lib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:020 (xine-lib).");
 script_set_attribute(attribute: "description", value: "Failure on Ogg files manipulation can lead remote attackers to cause
a denial of service by using crafted files (CVE-2008-3231).
Failure on manipulation of either MNG or Real or MOD files can lead
remote attackers to cause a denial of service by using crafted files
(CVE: CVE-2008-5233).
Heap-based overflow allows remote attackers to execute arbitrary
code by using Quicktime media files holding crafted metadata
(CVE-2008-5234).
Heap-based overflow allows remote attackers to execute arbitrary code
by using either crafted Matroska or Real media files (CVE-2008-5236).
Failure on manipulation of either MNG or Quicktime files can lead
remote attackers to cause a denial of service by using crafted files
(CVE-2008-5237).
Multiple heap-based overflow on input plugins (http, net, smb, dvd,
dvb, rtsp, rtp, pvr, pnm, file, gnome_vfs, mms) allow attackers to
execute arbitrary code by handling that input channels. Further
this problem can even lead attackers to cause denial of service
(CVE-2008-5239).
Heap-based overflow allows attackers to execute arbitrary code by using
crafted Matroska media files (MATROSKA_ID_TR_CODECPRIVATE track entry
element). Further a failure on handling of Real media files (CONT_TAG
header) can lead to a denial of service attack (CVE-2008-5240).
Integer underflow allows remote attackers to cause denial of service
by using Quicktime media files (CVE-2008-5241).
Failure on manipulation of Real media files can lead remote attackers
to cause a denial of service by indexing an allocated buffer with a
certain input value in a crafted file (CVE-2008-5243).
Vulnerabilities of unknown impact - possibly buffer overflow - caused
by a condition of video frame preallocation before ascertaining the
required length in V4L video input plugin (CVE-2008-5245).
Heap-based overflow allows remote attackers to execute arbitrary
code by using crafted media files. This vulnerability is in the
manipulation of ID3 audio file data tagging mainly used in MP3 file
formats (CVE-2008-5246).
This update provides the fix for all these security issues found in
xine-lib 1.1.11 of Mandriva 2008.1. The vulnerabilities: CVE-2008-5234,
CVE-2008-5236, CVE-2008-5237, CVE-2008-5239, CVE-2008-5240,
CVE-2008-5243 are found in xine-lib 1.1.15 of Mandriva 2009.0 and
are also fixed by this update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:020");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5243", "CVE-2008-5245", "CVE-2008-5246");
script_summary(english: "Check for the version of the xine-lib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxine1-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxine-devel-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-caca-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-image-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-jack-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-pulse-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-sdl-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-smb-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-wavpack-1.1.11.1-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxine1-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxine-devel-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-caca-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-image-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-jack-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-pulse-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-sdl-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-smb-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-wavpack-1.1.15-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xine-lib-", release:"MDK2008.1")
 || rpm_exists(rpm:"xine-lib-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-3231", value:TRUE);
 set_kb_item(name:"CVE-2008-5233", value:TRUE);
 set_kb_item(name:"CVE-2008-5234", value:TRUE);
 set_kb_item(name:"CVE-2008-5236", value:TRUE);
 set_kb_item(name:"CVE-2008-5237", value:TRUE);
 set_kb_item(name:"CVE-2008-5239", value:TRUE);
 set_kb_item(name:"CVE-2008-5240", value:TRUE);
 set_kb_item(name:"CVE-2008-5241", value:TRUE);
 set_kb_item(name:"CVE-2008-5243", value:TRUE);
 set_kb_item(name:"CVE-2008-5245", value:TRUE);
 set_kb_item(name:"CVE-2008-5246", value:TRUE);
}
exit(0, "Host is not affected");
