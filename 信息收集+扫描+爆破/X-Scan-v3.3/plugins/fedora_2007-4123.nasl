
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4123
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29269);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-4123: nagios");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4123 (nagios)");
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
ChangeLog:


Update information :

* Thu Nov 29 2007 Mike McGrath <mmcgrath redhat com> 2.10-3
- Upstream released 2.10
- Renamed cfg-sample configs to just .cfg
- Added BR of perl-devel, libjpeg-devel, libpng-devel
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5624");
script_summary(english: "Check for the version of the nagios package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"nagios-2.10-3.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
