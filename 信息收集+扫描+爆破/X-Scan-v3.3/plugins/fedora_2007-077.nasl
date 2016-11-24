
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-077
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24199);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 6 2007-077: w3m");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-077 (w3m)");
 script_set_attribute(attribute: "description", value: "The w3m program is a pager (or text file viewer) that can also be used
as a text-mode Web browser. W3m features include the following: when
reading an HTML document, you can follow links and view images using
an external image viewer; its internet message mode determines the
type of document from the header; if the Content-Type field of the
document is text/html, the document is displayed as an HTML document;
you can change a URL description like '[8]http://hogege.net' in plain
text into a link to that URL.
If you want to display the inline images on w3m, you need to install
w3m-img package as well.

Update Information:

- Resolves: rh#221484

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the w3m package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"w3m-img-0.5.1-15.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"w3m-0.5.1-15.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
