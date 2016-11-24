
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10972
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42382);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10972: python-4Suite-XML");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10972 (python-4Suite-XML)");
 script_set_attribute(attribute: "description", value: "4Suite-XML is a suite of Python modules for XML and RDF processing.
Its major components include the following:

* Ft.Xml.Domlette: A very fast, lightweight XPath-oriented DOM.
* Ft.Xml.XPath: An XPath 1.0 implementation for Domlette documents.
* Ft.Xml.Xslt: A robust XSLT 1.0 processor.
* Ft.Lib: Various support libraries that can be used independently.

-
Update Information:

Fixes a denial of service when handling malformed XML (CVE-2009-3720)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3720");
script_summary(english: "Check for the version of the python-4Suite-XML package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"python-4Suite-XML-1.0.2-8.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
