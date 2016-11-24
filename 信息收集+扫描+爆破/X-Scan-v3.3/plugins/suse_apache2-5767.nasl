
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34779);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for Apache 2 (apache2-5767)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apache2-5767");
 script_set_attribute(attribute: "description", value: "Missing sanity checks of FTP URLs allowed cross site
scripting (XSS) attacks via the mod_prody_ftp module
(CVE-2008-2939).

Missing precautions allowed cross site request forgery
(CSRF) via the mod_proxy_balancer interface (CVE-2007-6420)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch apache2-5767");
script_end_attributes();

script_cve_id("CVE-2007-6420", "CVE-2008-2939");
script_summary(english: "Check for the apache2-5767 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"apache2-2.2.3-16.17.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.2.3-16.17.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-doc-2.2.3-16.17.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-example-pages-2.2.3-16.17.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.2.3-16.17.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.2.3-16.17.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
