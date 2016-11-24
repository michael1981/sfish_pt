
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35245);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  courier-authlib security update (courier-authlib-5871)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch courier-authlib-5871");
 script_set_attribute(attribute: "description", value: "Insufficient quoting allowed attackers to inject SQL
statements when using the pgsql backend (CVE-2008-2380).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch courier-authlib-5871");
script_end_attributes();

script_cve_id("CVE-2008-2380");
script_summary(english: "Check for the courier-authlib-5871 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"courier-authlib-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-devel-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-ldap-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-mysql-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-pgsql-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-pipe-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"courier-authlib-userdb-0.59.3-44.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
