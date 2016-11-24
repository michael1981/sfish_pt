
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5644
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38943);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-5644: freetype1");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5644 (freetype1)");
 script_set_attribute(attribute: "description", value: "The FreeType engine is a free and portable TrueType font rendering engine,
developed to provide TrueType support for a variety of platforms and
environments. FreeType is a library which can open and manages font files as
well as efficiently load, hint and render individual glyphs. FreeType is not a
font server or a complete text-rendering library.
This package contains the obsolote version 1.x of FreeType for applications
which still need this old version. New applications should use the more
advanced FreeType 2.x library packaged as freetype.

-
Update Information:

Port of freetype2 security fixes
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2754");
script_summary(english: "Check for the version of the freetype1 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"freetype1-1.4-0.8.pre.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
