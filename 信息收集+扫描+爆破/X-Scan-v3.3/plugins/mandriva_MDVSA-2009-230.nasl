
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40966);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:230: pidgin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:230 (pidgin).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilities has been identified and fixed in pidgin:
The msn_slplink_process_msg function in
libpurple/protocols/msn/slplink.c in libpurple, as used in Pidgin
(formerly Gaim) before 2.5.9 and Adium 1.3.5 and earlier, allows
remote attackers to execute arbitrary code or cause a denial of service
(memory corruption and application crash) by sending multiple crafted
SLP (aka MSNSLP) messages to trigger an overwrite of an arbitrary
memory location. NOTE: this issue reportedly exists because of an
incomplete fix for CVE-2009-1376 (CVE-2009-2694).
Unspecified vulnerability in Pidgin 2.6.0 allows remote attackers
to cause a denial of service (crash) via a link in a Yahoo IM
(CVE-2009-3025)
protocols/jabber/auth.c in libpurple in Pidgin 2.6.0, and possibly
other versions, does not follow the require TLS/SSL preference
when connecting to older Jabber servers that do not follow the XMPP
specification, which causes libpurple to connect to the server without
the expected encryption and allows remote attackers to sniff sessions
(CVE-2009-3026).
libpurple/protocols/irc/msgs.c in the IRC protocol plugin in libpurple
in Pidgin before 2.6.2 allows remote IRC servers to cause a denial
of service (NULL pointer dereference and application crash) via a
TOPIC message that lacks a topic string (CVE-2009-2703).
The msn_slp_sip_recv function in libpurple/protocols/msn/slp.c in the
MSN protocol plugin in libpurple in Pidgin before 2.6.2 allows remote
attackers to cause a denial of service (NULL pointer dereference
and application crash) via an SLP invite message that lacks certain
required fields, as demonstrated by a malformed message from a KMess
client (CVE-2009-3083).
The msn_slp_process_msg function in libpurple/protocols/msn/slpcall.c
in the MSN protocol plugin in libpurple 2.6.0 and 2.6.1, as used in
Pidgin before 2.6.2, allows remote attackers to cause a denial of
service (application crash) via a handwritten (aka Ink) message,
related to an uninitialized variable and the incorrect UTF16-LE
charset name (CVE-2009-3084).
The XMPP protocol plugin in libpurple in Pidgin before 2.6.2 does
not properly handle an error IQ stanza during an attempted fetch of
a custom smiley, which allows remote attackers to cause a denial of
service (application crash) via XHTML-IM content with cid: images
(CVE-2009-3085).
This update provides pidgin 2.6.2, which is not vulnerable to these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:230");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1376", "CVE-2009-2694", "CVE-2009-2703", "CVE-2009-3025", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3084", "CVE-2009-3085");
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

if ( rpm_check( reference:"finch-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfinch0-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple0-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-bonjour-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-client-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-gevolution-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-i18n-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-meanwhile-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-mono-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-plugins-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-silc-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-tcl-2.6.2-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfinch0-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple0-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-bonjour-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-client-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-gevolution-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-i18n-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-meanwhile-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-mono-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-plugins-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-silc-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-tcl-2.6.2-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pidgin-", release:"MDK2009.0")
 || rpm_exists(rpm:"pidgin-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1376", value:TRUE);
 set_kb_item(name:"CVE-2009-2694", value:TRUE);
 set_kb_item(name:"CVE-2009-2703", value:TRUE);
 set_kb_item(name:"CVE-2009-3025", value:TRUE);
 set_kb_item(name:"CVE-2009-3026", value:TRUE);
 set_kb_item(name:"CVE-2009-3083", value:TRUE);
 set_kb_item(name:"CVE-2009-3084", value:TRUE);
 set_kb_item(name:"CVE-2009-3085", value:TRUE);
}
exit(0, "Host is not affected");
