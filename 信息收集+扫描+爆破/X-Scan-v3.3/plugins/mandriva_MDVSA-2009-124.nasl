
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39761);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:124-1: apache");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:124-1 (apache).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in apache:
Memory leak in the zlib_stateful_init function in crypto/comp/c_zlib.c
in libssl in OpenSSL 0.9.8f through 0.9.8h allows remote attackers to
cause a denial of service (memory consumption) via multiple calls, as
demonstrated by initial SSL client handshakes to the Apache HTTP Server
mod_ssl that specify a compression algorithm (CVE-2008-1678). Note
that this security issue does not really apply as zlib compression
is not enabled in the openssl build provided by Mandriva, but apache
is patched to address this issue anyway (conserns 2008.1 only).
Cross-site scripting (XSS) vulnerability in proxy_ftp.c in the
mod_proxy_ftp module in Apache 2.0.63 and earlier, and mod_proxy_ftp.c
in the mod_proxy_ftp module in Apache 2.2.9 and earlier 2.2 versions,
allows remote attackers to inject arbitrary web script or HTML via
wildcards in a pathname in an FTP URI (CVE-2008-2939). Note that this
security issue was initially addressed with MDVSA-2008:195 but the
patch fixing the issue was added but not applied in 2009.0.
The Apache HTTP Server 2.2.11 and earlier 2.2 versions does not
properly handle Options=IncludesNOEXEC in the AllowOverride directive,
which allows local users to gain privileges by configuring (1) Options
Includes, (2) Options +Includes, or (3) Options +IncludesNOEXEC in a
.htaccess file, and then inserting an exec element in a .shtml file
(CVE-2009-1195).
This update provides fixes for these vulnerabilities.
Update:
The patch for fixing CVE-2009-1195 for Mandriva Linux 2008.1 was
incomplete, this update addresses the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:124-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1678", "CVE-2008-2939", "CVE-2009-1195");
script_summary(english: "Check for the version of the apache package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-base-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-devel-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-htcacheclean-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_authn_dbd-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_cache-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_dav-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_dbd-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_deflate-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_disk_cache-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_file_cache-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_ldap-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_mem_cache-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_proxy-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_proxy_ajp-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_ssl-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-modules-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_userdir-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mpm-event-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mpm-itk-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mpm-prefork-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mpm-worker-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-source-2.2.8-6.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apache-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1678", value:TRUE);
 set_kb_item(name:"CVE-2008-2939", value:TRUE);
 set_kb_item(name:"CVE-2009-1195", value:TRUE);
}
exit(0, "Host is not affected");
