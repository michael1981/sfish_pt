
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10323
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37222);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-10323: nagios");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10323 (nagios)");
 script_set_attribute(attribute: "description", value: "Nagios is a program that will monitor hosts and services on your
network.  It has the ability to send email or page alerts when a
problem arises and when a problem is resolved.  Nagios is written
in C and is designed to run under Linux (and some other *NIX
variants) as a background process, intermittently running checks
on various services that you specify.

The actual service checks are performed by separate 'plugin' programs
which return the status of the checks to Nagios. The plugins are
available at [9]http://sourceforge.net/projects/nagiosplug.

This package provides the core program, web interface, and documentation
files for Nagios. Development files are built as a separate package.

-
Update Information:

Upstream has released a new version:        * Security fix for Cross Site
Request Forgery (CSRF) bug reported by Tim Starling.      * Sample audio files
for CGIs removed from distribution      * Fix for mutliline config file
continuation bug      * Minor fix to RPM spec file      * Fix for AIX compiler
warnings      * Minor sample config file fix      * Added documentation on CGI
security issues
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5027");
script_summary(english: "Check for the version of the nagios package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"nagios-3.0.5-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
