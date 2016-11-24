
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37535);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:219: mplayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:219 (mplayer).");
 script_set_attribute(attribute: "description", value: "A vulnerability that was discovered in xine-lib that allowed remote
RTSP servers to execute arbitrary code via a large streamid SDP
parameter also affects MPlayer (CVE-2008-0073).
Several integer overflows were discovered by Felipe Andres Manzano
in MPlayer's Real video stream demuxing code. These vulnerabilities
could allow an attacker to cause a crash or possibly execute arbitrary
code by supplying a malicious crafted video file (CVE-2008-3827).
The updated packages have been patched to fix these issues.
Note that CVE-2008-3827 was already corrected in the Mandriva Linux
2009 packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:219");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-0073", "CVE-2008-3827");
script_summary(english: "Check for the version of the mplayer package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libdha1.0-1.0-1.rc1.20.5mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.rc1.20.5mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.rc1.20.5mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-doc-1.0-1.rc1.20.5mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.rc1.20.5mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.rc2.10.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.rc2.10.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-doc-1.0-1.rc2.10.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.rc2.10.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.rc2.18.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.rc2.18.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-doc-1.0-1.rc2.18.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.rc2.18.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK2008.0")
 || rpm_exists(rpm:"mplayer-", release:"MDK2008.1")
 || rpm_exists(rpm:"mplayer-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-0073", value:TRUE);
 set_kb_item(name:"CVE-2008-3827", value:TRUE);
}
exit(0, "Host is not affected");
