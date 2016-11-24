
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2656
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31688);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2656: php-pear-PhpDocumentor");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2656 (php-pear-PhpDocumentor)");
 script_set_attribute(attribute: "description", value: "phpDocumentor is the current standard auto-documentation tool for the
php language. phpDocumentor has support for linking between documentation,
incorporating user level documents like tutorials and creation of
highlighted source code with cross referencing to php general
documentation.

phpDocumentor uses an extensive templating system to change your source
code comments into human readable, and hence useful, formats. This system
allows the creation of easy to read documentation in 15 different
pre-designed HTML versions, PDF format, Windows Helpfile CHM format, and
in Docbook XML.

-
Update Information:

Use system Smarty, instead of packaging our own.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1066");
script_summary(english: "Check for the version of the php-pear-PhpDocumentor package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-pear-PhpDocumentor-1.4.1-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
