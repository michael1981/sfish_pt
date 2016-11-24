
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27341);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  lighttpd: This update fixes a buffer overflow in the fcgi_env_add() function. (lighttpd-4532)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch lighttpd-4532");
 script_set_attribute(attribute: "description", value: "This update fixes a buffer overflow in the fcgi_env_add()
function. Under some circumstances this bug allows remote
code execution. (CVE-2007-4727)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch lighttpd-4532");
script_end_attributes();

script_cve_id("CVE-2007-4727");
script_summary(english: "Check for the lighttpd-4532 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"lighttpd-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"lighttpd-mod_cml-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"lighttpd-mod_magnet-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"lighttpd-mod_mysql_vhost-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"lighttpd-mod_rrdtool-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"lighttpd-mod_trigger_b4_dl-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"lighttpd-mod_webdav-1.4.18-1.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
