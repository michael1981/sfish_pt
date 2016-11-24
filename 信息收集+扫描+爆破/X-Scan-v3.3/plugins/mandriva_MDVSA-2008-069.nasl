
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38056);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:069: krb5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:069 (krb5).");
 script_set_attribute(attribute: "description", value: "Multiple memory management flaws were found in the GSSAPI library
used by Kerberos that could result in the use of already freed memory
or an attempt to free already freed memory, possibly leading to a
crash or allowing the execution of arbitrary code (CVE-2007-5901,
CVE-2007-5971).
A flaw was discovered in how the Kerberos krb5kdc handled Kerberos v4
protocol packets. An unauthenticated remote attacker could use this
flaw to crash the krb5kdc daemon, disclose portions of its memory,
or possibly %execute arbitrary code using malformed or truncated
Kerberos v4 protocol requests (CVE-2008-0062, CVE-2008-0063).
This issue only affects krb5kdc when it has Kerberos v4 protocol
compatibility enabled, which is a compiled-in default in all
Kerberos versions that Mandriva Linux ships prior to Mandriva
Linux 2008.0. Kerberos v4 protocol support can be disabled by
adding v4_mode=none (without quotes) to the [kdcdefaults] section
of /etc/kerberos/krb5kdc/kdc.conf.
A flaw in the RPC library as used in Kerberos' kadmind was discovered
by Jeff Altman of Secure Endpoints. An unauthenticated remote attacker
could use this vulnerability to crash kadmind or possibly execute
arbitrary code in systems with certain resource limits configured;
this does not affect the default resource limits used by Mandriva Linux
(CVE-2008-0947).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:069");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
script_summary(english: "Check for the version of the krb5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ftp-client-krb5-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkrb53-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkrb53-devel-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.5.2-6.6mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkrb53-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkrb53-devel-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.6.2-7.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK2007.1")
 || rpm_exists(rpm:"krb5-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-5901", value:TRUE);
 set_kb_item(name:"CVE-2007-5971", value:TRUE);
 set_kb_item(name:"CVE-2008-0062", value:TRUE);
 set_kb_item(name:"CVE-2008-0063", value:TRUE);
 set_kb_item(name:"CVE-2008-0947", value:TRUE);
}
exit(0, "Host is not affected");
