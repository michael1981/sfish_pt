# This script was automatically generated from the dsa-1336
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25779);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1336");
 script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0045", "CVE-2007-0775", "CVE-2007-0778", "CVE-2007-0981");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1336 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Mozilla Firefox.
This will be the last security update of Mozilla-based products for
the oldstable (sarge) distribution of Debian. We recommend to upgrade
to stable (etch) as soon as possible.
The Common Vulnerabilities and Exposures project identifies the following
vulnerabilities:
CVE-2007-1282
    It was discovered that an integer overflow in text/enhanced message
    parsing allows the execution of arbitrary code.
CVE-2007-0994
    It was discovered that a regression in the Javascript engine allows
    the execution of Javascript with elevated privileges.
CVE-2007-0995
    It was discovered that incorrect parsing of invalid HTML characters
    allows the bypass of content filters.
CVE-2007-0996
    It was discovered that insecure child frame handling allows cross-site
    scripting.
CVE-2007-0981
    It was discovered that Firefox handles URI with a null byte in the
    hostname insecurely.
CVE-2007-0008
    It was discovered that a buffer overflow in the NSS code allows the
    execution of arbitrary code.
CVE-2007-0009
    It was discovered that a buffer overflow in the NSS code allows the
    execution of arbitrary code.
CVE-2007-0775
    It was discovered that multiple programming errors in the layout engine
    allow the execution of arbitrary code.
CVE-2007-0778
    It was discovered that the page cache calculates hashes in an insecure
    manner.
CVE-2006-6077
    It was discovered that the password manager allows the disclosure of
    passwords.
For the oldstable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge17. You should upgrade to etch as soon as possible.
The stable distribution (etch) isn\'t affected. These vulnerabilities have
been fixed prior to the release of Debian etch.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1336');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2007/dsa-1336
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1336] DSA-1336-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1336-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge17');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge17');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge17');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
