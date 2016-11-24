
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8332
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40755);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-8332: xerces-c27");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8332 (xerces-c27)");
 script_set_attribute(attribute: "description", value: "Xerces-C is a validating XML parser written in a portable subset of C++.
Xerces-C makes it easy to give your application the ability to read and write
XML data. A shared library is provided for parsing, generating, manipulating,
and validating XML documents. Xerces-C is faithful to the XML 1.0
recommendation and associated standards ( DOM 1.0, DOM 2.0. SAX 1.0, SAX 2.0,
Namespaces).

Note that this package contains Xerces-C++ 2.7.0 for compatibility with
applications that cannot use a newer version.

-
Update Information:

CVE-2009-1885
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1885");
script_summary(english: "Check for the version of the xerces-c27 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xerces-c27-2.7.0-8.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
