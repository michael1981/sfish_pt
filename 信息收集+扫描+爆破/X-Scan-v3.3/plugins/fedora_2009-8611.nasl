
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8611
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40832);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-8611: htmldoc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8611 (htmldoc)");
 script_set_attribute(attribute: "description", value: "HTMLDOC converts HTML source files into indexed HTML, PostScript, or
Portable Document Format (PDF) files that can be viewed online or
printed. With no options a HTML document is produced on stdout.

The second form of HTMLDOC reads HTML source from stdin, which allows
you to use HTMLDOC as a filter.

The third form of HTMLDOC launches a graphical interface that allows
you to change options and generate documents interactively.

-
Update Information:

Fix scanf issues found by Gentoo. Fix FTBFS on Fedora 12.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the htmldoc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"htmldoc-1.8.27-12.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
