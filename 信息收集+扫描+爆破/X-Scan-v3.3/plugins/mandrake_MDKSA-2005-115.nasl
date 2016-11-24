
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18677);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2005:115: mplayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:115 (mplayer).");
 script_set_attribute(attribute: "description", value: "Two heap overflows were discovered in mplayer's code handling the
RealMedia RTSP and Microsoft Media Services streams over TCP (MMST).
These vulnerabilities could allow for a malicious server to execute
arbitrary code on the client computer with the permissions of the
user running MPlayer.
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:115");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1195");
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

if ( rpm_check( reference:"libdha1.0-1.0-0.pre5.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-0.pre5.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-0.pre5.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-0.pre5.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-0.pre5.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-0.pre5.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdha1.0-1.0-0.pre6.8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-0.pre6.8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-0.pre6.8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-0.pre6.8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-0.pre6.8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-0.pre6.8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK10.1")
 || rpm_exists(rpm:"mplayer-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1195", value:TRUE);
}
exit(0, "Host is not affected");
