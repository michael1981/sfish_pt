
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28282);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  apache2: Security update to fix various issues (apache2-4666)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apache2-4666");
 script_set_attribute(attribute: "description", value: "Several bugs were fixed in the Apache2 webserver:

These include the following security issues:

- CVE-2006-5752: mod_status: Fix a possible XSS attack
  against a site with a public server-status page and
  ExtendedStatus enabled, for browsers which perform
  charset 'detection'.
- CVE-2007-1863: mod_cache: Prevent a segmentation fault if
  attributes are listed in a Cache-Control header without
  any value.
- CVE-2007-3304: prefork, worker, event MPMs: Ensure that
  the parent process cannot be forced to kill processes
  outside its process group.
- CVE-2007-3847: mod_proxy: Prevent reading past the end of
  a buffer when parsing date-related headers. PR 41144.
- CVE-2007-4465: mod_autoindex: Add in ContentType and
  Charset options to IndexOptions directive. This allows
  the admin to explicitly set the content-type and charset
  of the generated page.

and the following non-security issues:

- get_module_list: replace loadmodule.conf atomically
- Use File::Temp to create good tmpdir in logresolve.pl2
  (httpd-2.x.x-logresolve.patchs)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch apache2-4666");
script_end_attributes();

script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304", "CVE-2007-3847", "CVE-2007-4465");
script_summary(english: "Check for the apache2-4666 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache2-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-doc-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-example-pages-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-utils-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.2.4-70.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
