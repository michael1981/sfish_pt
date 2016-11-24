# This script was automatically generated from the dsa-594
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15729);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "594");
 script_cve_id("CVE-2004-0940");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-594 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been identified in the Apache 1.3 webserver:
    "Crazy Einstein" has discovered a vulnerability in the
    "mod_include" module, which can cause a buffer to be overflown and
    could lead to the execution of arbitrary code.
    Larry Cashdollar has discovered a potential buffer overflow in the
    htpasswd utility, which could be exploited when user-supplied is
    passed to the program via a CGI (or PHP, or ePerl, ...) program.
For the stable distribution (woody) these problems have been fixed in
version 1.3.26-0woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-594');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apache packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA594] DSA-594-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-594-1 apache");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody6');
deb_check(prefix: 'apache-common', release: '3.0', reference: '1.3.26-0woody6');
deb_check(prefix: 'apache-dev', release: '3.0', reference: '1.3.26-0woody6');
deb_check(prefix: 'apache-doc', release: '3.0', reference: '1.3.26-0woody6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
