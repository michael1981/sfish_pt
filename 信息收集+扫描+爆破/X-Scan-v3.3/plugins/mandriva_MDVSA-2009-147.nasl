
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39582);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:147: pidgin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:147 (pidgin).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilities has been identified and fixed in pidgin:
Buffer overflow in the XMPP SOCKS5 bytestream server in Pidgin
(formerly Gaim) before 2.5.6 allows remote authenticated users to
execute arbitrary code via vectors involving an outbound XMPP file
transfer. NOTE: some of these details are obtained from third party
information (CVE-2009-1373).
Buffer overflow in the decrypt_out function in Pidgin (formerly Gaim)
before 2.5.6 allows remote attackers to cause a denial of service
(application crash) via a QQ packet (CVE-2009-1374).
The PurpleCircBuffer implementation in Pidgin (formerly Gaim) before
2.5.6 does not properly maintain a certain buffer, which allows
remote attackers to cause a denial of service (memory corruption
and application crash) via vectors involving the (1) XMPP or (2)
Sametime protocol (CVE-2009-1375).
Multiple integer overflows in the msn_slplink_process_msg functions in
the MSN protocol handler in (1) libpurple/protocols/msn/slplink.c and
(2) libpurple/protocols/msnp9/slplink.c in Pidgin (formerly Gaim)
before 2.5.6 on 32-bit platforms allow remote attackers to execute
arbitrary code via a malformed SLP message with a crafted offset
value, leading to buffer overflows. NOTE: this issue exists because
of an incomplete fix for CVE-2008-2927 (CVE-2009-1376).
This update provides pidgin 2.5.8, which is not vulnerable to these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:147");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2927", "CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");
script_summary(english: "Check for the version of the pidgin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"finch-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfinch0-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple0-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-bonjour-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-client-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-gevolution-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-i18n-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-meanwhile-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-mono-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-plugins-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-silc-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-tcl-2.5.8-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfinch0-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple0-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-bonjour-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-client-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-gevolution-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-i18n-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-meanwhile-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-mono-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-plugins-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-silc-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-tcl-2.5.8-0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pidgin-", release:"MDK2009.0")
 || rpm_exists(rpm:"pidgin-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2008-2927", value:TRUE);
 set_kb_item(name:"CVE-2009-1373", value:TRUE);
 set_kb_item(name:"CVE-2009-1374", value:TRUE);
 set_kb_item(name:"CVE-2009-1375", value:TRUE);
 set_kb_item(name:"CVE-2009-1376", value:TRUE);
}
exit(0, "Host is not affected");
