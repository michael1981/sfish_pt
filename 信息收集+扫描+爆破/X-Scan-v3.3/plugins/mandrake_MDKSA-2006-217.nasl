
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24602);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:217-1: proftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:217-1 (proftpd).");
 script_set_attribute(attribute: "description", value: "A stack-based buffer overflow in the sreplace function in ProFTPD 1.3.0
and earlier, allows remote attackers to cause a denial of service, as
demonstrated by vd_proftpd.pm, a 'ProFTPD remote exploit.'
(CVE-2006-5815)
Buffer overflow in the tls_x509_name_oneline function in the mod_tls
module, as used in ProFTPD 1.3.0a and earlier, and possibly other
products, allows remote attackers to execute arbitrary code via a large
data length argument, a different vulnerability than CVE-2006-5815.
(CVE-2006-6170)
ProFTPD 1.3.0a and earlier does not properly set the buffer size limit
when CommandBufferSize is specified in the configuration file, which
leads to an off-by-two buffer underflow. NOTE: in November 2006, the
role of CommandBufferSize was originally associated with CVE-2006-5815,
but this was an error stemming from an initial vague disclosure. NOTE:
ProFTPD developers dispute this issue, saying that the relevant memory
location is overwritten by assignment before further use within the
affected function, so this is not a vulnerability. (CVE-2006-6171)
Packages have been patched to correct these issues.
Update:
The previous update incorrectly linked the vd_proftd.pm issue with the
CommandBufferSize issue. These are two distinct issues and the previous
update only addressed CommandBufferSize (CVE-2006-6171), and the
mod_tls issue (CVE-2006-6170).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:217-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");
script_summary(english: "Check for the version of the proftpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"proftpd-1.2.10-13.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.10-13.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_autohost-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_case-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_clamav-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_ctrls_admin-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_facl-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_gss-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_ifsession-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_ldap-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_load-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_quotatab-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_quotatab_file-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_quotatab_ldap-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_quotatab_sql-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_radius-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_ratio-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_rewrite-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_shaper-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_site_misc-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_sql-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_sql_mysql-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_sql_postgres-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_time-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_tls-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_wrap-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_wrap_file-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-mod_wrap_sql-1.3.0-4.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"proftpd-", release:"MDK2006.0")
 || rpm_exists(rpm:"proftpd-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-5815", value:TRUE);
 set_kb_item(name:"CVE-2006-6170", value:TRUE);
 set_kb_item(name:"CVE-2006-6171", value:TRUE);
}
exit(0, "Host is not affected");
