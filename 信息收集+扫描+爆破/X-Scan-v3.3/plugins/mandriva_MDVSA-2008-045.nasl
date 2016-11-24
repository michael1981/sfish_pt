
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37405);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:045: mplayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:045 (mplayer).");
 script_set_attribute(attribute: "description", value: "Heap-based buffer overflow in the rmff_dump_cont function in
input/libreal/rmff.c in xine-lib 1.1.9 and earlier allows remote
attackers to execute arbitrary code via the SDP Abstract attribute,
related to the rmff_dump_header function and related to disregarding
the max field. Although originally a xine-lib issue, also affects
MPlayer due to code similarity. (CVE-2008-0225)
Multiple heap-based buffer overflows in the rmff_dump_cont function
in input/libreal/rmff.c in xine-lib 1.1.9 allow remote attackers
to execute arbitrary code via the SDP (1) Title, (2) Author, or
(3) Copyright attribute, related to the rmff_dump_header function,
different vectors than CVE-2008-0225. Although originally a xine-lib
issue, also affects MPlayer due to code similarity. (CVE-2008-0238)
Array index error in libmpdemux/demux_mov.c in MPlayer 1.0 rc2 and
earlier might allow remote attackers to execute arbitrary code via
a QuickTime MOV file with a crafted stsc atom tag. (CVE-2008-0485)
Array index vulnerability in libmpdemux/demux_audio.c in MPlayer
1.0rc2 and SVN before r25917, and possibly earlier versions, as
used in Xine-lib 1.1.10, might allow remote attackers to execute
arbitrary code via a crafted FLAC tag, which triggers a buffer
overflow. (CVE-2008-0486)
Buffer overflow in stream_cddb.c in MPlayer 1.0rc2 and SVN
before r25824 allows remote user-assisted attackers to execute
arbitrary code via a CDDB database entry containing a long album
title. (CVE-2008-0629)
Buffer overflow in url.c in MPlayer 1.0rc2 and SVN before r25823 allows
remote attackers to execute arbitrary code via a crafted URL that
prevents the IPv6 parsing code from setting a pointer to NULL, which
causes the buffer to be reused by the unescape code. (CVE-2008-0630)
The updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:045");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-0225", "CVE-2008-0238", "CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");
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

if ( rpm_check( reference:"libdha1.0-1.0-1.rc1.11.5mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.rc1.11.5mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.rc1.11.5mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-doc-1.0-1.rc1.11.5mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.rc1.11.5mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdha1.0-1.0-1.rc1.20.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.rc1.20.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.rc1.20.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-doc-1.0-1.rc1.20.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.rc1.20.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK2007.1")
 || rpm_exists(rpm:"mplayer-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2008-0225", value:TRUE);
 set_kb_item(name:"CVE-2008-0238", value:TRUE);
 set_kb_item(name:"CVE-2008-0485", value:TRUE);
 set_kb_item(name:"CVE-2008-0486", value:TRUE);
 set_kb_item(name:"CVE-2008-0629", value:TRUE);
 set_kb_item(name:"CVE-2008-0630", value:TRUE);
}
exit(0, "Host is not affected");
