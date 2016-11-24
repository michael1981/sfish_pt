
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10329
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42267);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10329: python-markdown2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10329 (python-markdown2)");
 script_set_attribute(attribute: "description", value: "Markdown is a text-to-HTML filter; it translates an easy-to-read /
easy-to-write structured text format into HTML. Markdown's text format
is most similar to that of plain text email, and supports features
such as headers, emphasis, code blocks, blockquotes, and links.

This is a fast and complete Python implementation of the Markdown
spec.

For information about markdown itself, see
[9]http://daringfireball.net/projects/markdown/

-
Update Information:

Update from 1.0.1.11 to 1.0.1.15, which fixes some issues, including these two
security-related bugs:  - [Issue 30] Fix a possible XSS via JavaScript injectio
n
in a carefully crafted image reference (usage of double-quotes in the URL).  -
[Issue 29] Fix security hole in the md5-hashing scheme for handling HTML chunks
during processing.    See [10]http://code.google.com/p/python-
markdown2/source/browse/trunk/CHANGES.txt for the full changelog.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the python-markdown2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"python-markdown2-1.0.1.15-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
