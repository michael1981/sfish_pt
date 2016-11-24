
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6014
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39504);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-6014: apr-util");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6014 (apr-util)");
 script_set_attribute(attribute: "description", value: "The mission of the Apache Portable Runtime (APR) is to provide a
free library of C data structures and routines.  This library
contains additional utility interfaces for APR; including support
for XML, LDAP, database interfaces, URI parsing and more.

-
Update Information:

Backport security fixes from upstream version 1.3.7:  - CVE-2009-0023 Fix
underflow in apr_strmatch_precompile.  - CVE-2009-1955 Fix a denial of service
attack against the apr_xml_* interface using the 'billion laughs' entity
expansion technique.  - CVE-2009-1956 Fix off by one overflow in
apr_brigade_vprintf.    Note: CVE-2009-1956 is only an issue on big-endian
architectures.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
script_summary(english: "Check for the version of the apr-util package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"apr-util-1.2.12-7.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
