# This script was automatically generated from the dsa-1539
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31809);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1539");
 script_cve_id("CVE-2007-4542", "CVE-2007-4629");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1539 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Schmidt and Daniel Morissette discovered two vulnerabilities
in mapserver, a development environment for spatial and mapping
applications.  The Common Vulnerabilities and Exposures project
identifies the following two problems:
CVE-2007-4542
    Lack of input sanitizing and output escaping in the CGI
    mapserver\'s template handling and error reporting routines leads
    to cross-site scripting vulnerabilities.
CVE-2007-4629
    Missing bounds checking in mapserver\'s template handling leads to
    a stack-based buffer overrun vulnerability, allowing a remote
    attacker to execute arbitrary code with the privileges of the CGI
    or httpd user.
For the stable distribution (etch), these problems have been fixed in
version 4.10.0-5.1+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1539');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mapserver (4.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1539] DSA-1539-1 mapserver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1539-1 mapserver");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cgi-mapserver', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'mapserver-bin', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'mapserver-doc', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'perl-mapscript', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'php4-mapscript', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'php5-mapscript', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'python-mapscript', release: '4.0', reference: '4.10.0-5.1+etch2');
deb_check(prefix: 'mapserver', release: '4.0', reference: '4.10.0-5.1+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
