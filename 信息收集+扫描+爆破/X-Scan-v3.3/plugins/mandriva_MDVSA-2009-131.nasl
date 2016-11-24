
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39323);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:131: apr-util");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:131 (apr-util).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed
in apr-util:
The apr_strmatch_precompile function in strmatch/apr_strmatch.c in
Apache APR-util before 1.3.5 allows remote attackers to cause a denial
of service (daemon crash) via crafted input involving (1) a .htaccess
file used with the Apache HTTP Server, (2) the SVNMasterURI directive
in the mod_dav_svn module in the Apache HTTP Server, (3) the mod_apreq2
module for the Apache HTTP Server, or (4) an application that uses
the libapreq2 library, related to an underflow flaw. (CVE-2009-0023).
The expat XML parser in the apr_xml_* interface in xml/apr_xml.c in
Apache APR-util before 1.3.7, as used in the mod_dav and mod_dav_svn
modules in the Apache HTTP Server, allows remote attackers to
cause a denial of service (memory consumption) via a crafted XML
document containing a large number of nested entity references, as
demonstrated by a PROPFIND request, a similar issue to CVE-2003-1564
(CVE-2009-1955).
Off-by-one error in the apr_brigade_vprintf function in Apache APR-util
before 1.3.5 on big-endian platforms allows remote attackers to obtain
sensitive information or cause a denial of service (application crash)
via crafted input (CVE-2009-1956).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:131");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-1564", "CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
script_summary(english: "Check for the version of the apr-util package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apr-util-dbd-mysql-1.2.12-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-pgsql-1.2.12-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-sqlite3-1.2.12-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libapr-util1-1.2.12-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libapr-util-devel-1.2.12-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-freetds-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-ldap-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-mysql-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-odbc-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-pgsql-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-sqlite3-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libapr-util1-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libapr-util-devel-1.3.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-freetds-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-ldap-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-mysql-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-odbc-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-pgsql-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-dbd-sqlite3-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libapr-util1-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libapr-util-devel-1.3.4-9.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apr-util-", release:"MDK2008.1")
 || rpm_exists(rpm:"apr-util-", release:"MDK2009.0")
 || rpm_exists(rpm:"apr-util-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2003-1564", value:TRUE);
 set_kb_item(name:"CVE-2009-0023", value:TRUE);
 set_kb_item(name:"CVE-2009-1955", value:TRUE);
 set_kb_item(name:"CVE-2009-1956", value:TRUE);
}
exit(0, "Host is not affected");
