
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39322);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:130: gstreamer0.10-plugins-good");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:130 (gstreamer0.10-plugins-good).");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows in the (1) user_info_callback,
(2) user_endrow_callback, and (3) gst_pngdec_task functions
(ext/libpng/gstpngdec.c) in GStreamer Good Plug-ins (aka
gst-plugins-good or gstreamer-plugins-good) 0.10.15 allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via a crafted PNG file, which triggers a buffer overflow
(CVE-2009-1932).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:130");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1932");
script_summary(english: "Check for the version of the gstreamer0.10-plugins-good package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gstreamer0.10-aalib-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-caca-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-dv-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-esound-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-flac-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-plugins-good-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-raw1394-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-speex-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-wavpack-0.10.7-3.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-aalib-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-caca-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-dv-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-esound-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-flac-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-plugins-good-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-pulse-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-raw1394-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-soup-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-speex-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-wavpack-0.10.10-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-aalib-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-caca-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-dv-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-esound-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-flac-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-plugins-good-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-pulse-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-raw1394-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-soup-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-speex-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer0.10-wavpack-0.10.14-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gstreamer0.10-plugins-good-", release:"MDK2008.1")
 || rpm_exists(rpm:"gstreamer0.10-plugins-good-", release:"MDK2009.0")
 || rpm_exists(rpm:"gstreamer0.10-plugins-good-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1932", value:TRUE);
}
exit(0, "Host is not affected");
