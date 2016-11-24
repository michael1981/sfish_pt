
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31766);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  apache2 security update (apache2-5126)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apache2-5126");
 script_set_attribute(attribute: "description", value: "This update fixes multiple bugs in apache:

- cross site scripting problem in mod_imap (CVE-2007-5000)

- cross site scripting problem in mod_status (CVE-2007-6388)

- cross site scripting problem in the ftp proxy module
  (CVE-2008-0005)

- cross site scripting problem in the error page for status
  code 413 (CVE-2007-6203)

- cross site scripting problem in mod_proxy_balancer
  (CVE-2007-6421)

- A flaw in mod_proxy_balancer allowed attackers to crash
  apache (CVE-2007-6422)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch apache2-5126");
script_end_attributes();

script_cve_id("CVE-2007-5000", "CVE-2007-6388", "CVE-2008-0005", "CVE-2007-6203", "CVE-2007-6421", "CVE-2007-6422");
script_summary(english: "Check for the apache2-5126 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache2-2.2.3-24", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.2.3-24", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-doc-2.2.3-24", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-example-pages-2.2.3-24", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.2.3-24", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.2.3-24", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
