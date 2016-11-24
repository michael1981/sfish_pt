
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2224
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27761);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2224: elinks");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2224 (elinks)");
 script_set_attribute(attribute: "description", value: "Links is a text-based Web browser. Links does not display any images,
but it does support frames, tables and most other HTML tags. Links'
advantage over graphical browsers is its speed--Links starts and exits
quickly and swiftly displays Web pages.

-
Update Information:

Update done because of security issue in elinks 0.11.2 , in this update are inc
luded other changes done in devel branch meanwhile(license tags,open macro,lice
nse file missing,duplicate buildrequires).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5034");
script_summary(english: "Check for the version of the elinks package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"elinks-0.11.3-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
