# This script was automatically generated from the dsa-767
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19316);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "767");
 script_cve_id("CVE-2005-1852");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-767 security update');
 script_set_attribute(attribute: 'description', value:
'Marcin Slusarz discovered two integer overflow vulnerabilities in
libgadu, a library provided and used by ekg, a console Gadu Gadu
client, an instant messaging program, that could lead to the execution
of arbitrary code.
The library is also used by other packages such as kopete, which
should be restarted to take effect of this update.
The old stable distribution (woody) does not contain an ekg package.
For the stable distribution (sarge) these problems have been fixed in
version 1.5+20050411-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-767');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ekg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA767] DSA-767-1 ekg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-767-1 ekg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-5');
deb_check(prefix: 'libgadu-dev', release: '3.1', reference: '1.5+20050411-5');
deb_check(prefix: 'libgadu3', release: '3.1', reference: '1.5+20050411-5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
