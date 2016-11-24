
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3907
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28344);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-3907: htdig");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3907 (htdig)");
 script_set_attribute(attribute: "description", value: "The ht://Dig system is a complete world wide web indexing and searching
system for a small domain or intranet. This system is not meant to replace
the need for powerful internet-wide search systems like Lycos, Infoseek,
Webcrawler and AltaVista. Instead it is meant to cover the search needs for
a single company, campus, or even a particular sub section of a web site. As
opposed to some WAIS-based or web-server based search engines, ht://Dig can
span several web servers at a site. The type of these different web servers
doesn't matter as long as they understand the HTTP 1.0 protocol.
ht://Dig is also used by KDE to search KDE's HTML documentation.

ht://Dig was developed at San Diego State University as a way to search the
various web servers on the campus network.

-
Update Information:

- CVE-2007-6110
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6110");
script_summary(english: "Check for the version of the htdig package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"htdig-3.2.0b6-12.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
