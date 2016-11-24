
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2767
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31692);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2767: namazu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2767 (namazu)");
 script_set_attribute(attribute: "description", value: "Namazu is a full-text search engine software intended for easy use.
Not only it works as CGI program for small or medium scale WWW
search engine, but also works as personal use such as search system
for local HDD.

-
ChangeLog:


Update information :

* Mon Mar 24 2008 Akira TAGOH <tagoh redhat com> - 2.0.18-1
- security fix (#438664)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1468");
script_summary(english: "Check for the version of the namazu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"namazu-2.0.18-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
