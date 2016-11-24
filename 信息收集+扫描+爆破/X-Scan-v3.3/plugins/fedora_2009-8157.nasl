
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8157
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40454);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 11 2009-8157: xml-security-c");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8157 (xml-security-c)");
 script_set_attribute(attribute: "description", value: "The xml-security-c library is a C++ implementation of the XML Digital Signature
specification. The library makes use of the Apache XML project's Xerces-C XML
Parser and Xalan-C XSLT processor. The latter is used for processing XPath and
XSLT transforms.

-
Update Information:

Fixes CVE-2009-0217 (#511915)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0217");
script_summary(english: "Check for the version of the xml-security-c package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xml-security-c-1.5.1-1.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
