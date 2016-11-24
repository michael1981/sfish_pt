# This script was automatically generated from the dsa-805
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19612);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "805");
 script_cve_id("CVE-2005-1268", "CVE-2005-2088", "CVE-2005-2700", "CVE-2005-2728");
 script_bugtraq_id(14660);
 script_xref(name: "CERT", value: "744929");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-805 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in Apache2, the next generation,
scalable, extendable web server.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Marc Stern discovered an off-by-one error in the mod_ssl
    Certificate Revocation List (CRL) verification callback.  When
    Apache is configured to use a CRL this can be used to cause a
    denial of service.
    A vulnerability has been discovered in the Apache web server.
    When it is acting as an HTTP proxy, it allows remote attackers to
    poison the web cache, bypass web application firewall protection,
    and conduct cross-site scripting attacks, which causes Apache to
    incorrectly handle and forward the body of the request.
    A problem has been discovered in mod_ssl, which provides strong
    cryptography (HTTPS support) for Apache that allows remote
    attackers to bypass access restrictions.
    The byte-range filter in Apache 2.0 allows remote attackers to
    cause a denial of service via an HTTP header with a large Range
    field.
The old stable distribution (woody) does not contain Apache2 packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.54-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-805');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apache2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA805] DSA-805-1 apache2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-805-1 apache2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache2', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-common', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-doc', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-mpm-perchild', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-mpm-prefork', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-mpm-threadpool', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-mpm-worker', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-prefork-dev', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-threaded-dev', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'apache2-utils', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'libapr0', release: '3.1', reference: '2.0.54-5');
deb_check(prefix: 'libapr0-dev', release: '3.1', reference: '2.0.54-5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
