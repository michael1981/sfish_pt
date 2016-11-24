
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33223);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  courier-authlib: SQL injection (courier-authlib-5352)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch courier-authlib-5352");
 script_set_attribute(attribute: "description", value: "This update of courier-authlib fixes a bug that allowed
SQL injections. (CVE-2008-2667)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch courier-authlib-5352");
script_end_attributes();

script_cve_id("CVE-2008-2667");
script_summary(english: "Check for the courier-authlib-5352 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"courier-authlib-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-devel-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-ldap-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-mysql-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-pgsql-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-pipe-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-userdb-0.59.3-44.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
