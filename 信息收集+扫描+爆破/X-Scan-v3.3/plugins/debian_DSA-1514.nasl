# This script was automatically generated from the dsa-1514
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31425);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1514");
 script_cve_id("CVE-2007-2423", "CVE-2007-2637", "CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1514 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in MoinMoin, a
Python clone of WikiWiki. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2007-2423
    A cross-site-scripting vulnerability has been discovered in
    attachment handling.
CVE-2007-2637
    Access control lists for calendars and includes were
    insufficiently enforced, which could lead to information
    disclosure.
CVE-2008-0780
    A cross-site-scripting vulnerability has been discovered in
    the login code.
CVE-2008-0781
    A cross-site-scripting vulnerability has been discovered in
    attachment handling.
CVE-2008-0782
    A directory traversal vulnerability in cookie handling could
    lead to local denial of service by overwriting files.
CVE-2008-1098
    Cross-site-scripting vulnerabilities have been discovered in
    the GUI editor formatter and the code to delete pages.
CVE-2008-1099
    The macro code validates access control lists insufficiently,
    which could lead to information disclosure.
For the stable distribution (etch), these problems have been fixed in
version 1.5.3-1.2etch1. This update also includes a bugfix with respect to the
encoding of password reminder mails, which doesn\'t have security
implications.
The old stable distribution (sarge) will not be updated due to
the many changes and support for Sarge ending end of this month
anyway. You\'re advised to upgrade to the stable distribution if
you run moinmoin.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1514');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your moin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1514] DSA-1514-1 moin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1514-1 moin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'moinmoin-common', release: '4.0', reference: '1.5.3-1.2etch1');
deb_check(prefix: 'python-moinmoin', release: '4.0', reference: '1.5.3-1.2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
