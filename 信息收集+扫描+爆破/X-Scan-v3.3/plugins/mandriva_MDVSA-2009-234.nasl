
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40997);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:234: silc-toolkit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:234 (silc-toolkit).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities was discovered and corrected in silc-toolkit:
Multiple format string vulnerabilities in lib/silcclient/client_entry.c
in Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10, and
SILC Client before 1.1.8, allow remote attackers to execute arbitrary
code via format string specifiers in a nickname field, related to the
(1) silc_client_add_client, (2) silc_client_update_client, and (3)
silc_client_nickname_format functions (CVE-2009-3051).
The silc_asn1_encoder function in lib/silcasn1/silcasn1_encode.c in
Secure Internet Live Conferencing (SILC) Toolkit before 1.1.8 allows
remote attackers to overwrite a stack location and possibly execute
arbitrary code via a crafted OID value, related to incorrect use of
a %lu format string (CVE-2008-7159).
The silc_http_server_parse function in lib/silchttp/silchttpserver.c in
the internal HTTP server in silcd in Secure Internet Live Conferencing
(SILC) Toolkit before 1.1.9 allows remote attackers to overwrite
a stack location and possibly execute arbitrary code via a crafted
Content-Length header, related to incorrect use of a %lu format string
(CVE-2008-7160).
Multiple format string vulnerabilities in lib/silcclient/command.c
in Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10,
and SILC Client 1.1.8 and earlier, allow remote attackers to execute
arbitrary code via format string specifiers in a channel name, related
to (1) silc_client_command_topic, (2) silc_client_command_kick,
(3) silc_client_command_leave, and (4) silc_client_command_users
(CVE-2009-3163).
This update provides a solution to these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:234");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3051", "CVE-2009-3163");
script_summary(english: "Check for the version of the silc-toolkit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsilc1.1_2-1.1.7-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsilcclient1.1_2-1.1.7-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"silc-toolkit-1.1.7-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"silc-toolkit-devel-1.1.7-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsilc1.1_2-1.1.7-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsilcclient1.1_2-1.1.7-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"silc-toolkit-1.1.7-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"silc-toolkit-devel-1.1.7-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"silc-toolkit-", release:"MDK2008.1")
 || rpm_exists(rpm:"silc-toolkit-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-7159", value:TRUE);
 set_kb_item(name:"CVE-2008-7160", value:TRUE);
 set_kb_item(name:"CVE-2009-3051", value:TRUE);
 set_kb_item(name:"CVE-2009-3163", value:TRUE);
}
exit(0, "Host is not affected");
