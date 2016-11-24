#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(25095);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2007-0153");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2007-0153.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2007-0153.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
script_end_attributes();

script_cve_id("CVE-2007-0455","CVE-2007-1001","CVE-2007-1583","CVE-2007-1718");

 script_summary(english:"Checks for missing updates on the remote CentOS system");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"CentOS Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/CentOS/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/CentOS/rpm-list") ) exit(1, "Could not obtain the list of packages");

if ( rpm_check(reference:"php-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-bcmath-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-cli-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-common-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-dba-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-devel-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-gd-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-imap-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-ldap-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-mbstring-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-mysql-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-ncurses-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-odbc-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-pdo-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-pgsql-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-snmp-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-soap-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-xml-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-xmlrpc-5.1.6-11.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-bcmath-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-cli-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-common-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-dba-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-devel-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-gd-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-imap-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-ldap-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-mbstring-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-mysql-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-ncurses-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-odbc-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-pdo-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-pgsql-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-snmp-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-soap-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-xml-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"php-xmlrpc-5.1.6-11.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
