# This script was automatically generated from the dsa-1810
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38991);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1810");
 script_cve_id("CVE-2008-5519");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1810 security update');
 script_set_attribute(attribute: 'description', value:
'An information disclosure flaw was found in mod_jk, the Tomcat Connector
module for Apache. If a buggy client included the "Content-Length" header
without providing request body data, or if a client sent repeated 
requests very quickly, one client could obtain a response intended for
another client.
The oldstable distribution (etch), this problem has been fixed in
version 1:1.2.18-3etch2.
For the stable distribution (lenny), this problem has been fixed in
version 1:1.2.26-2+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1810');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-jk packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1810] DSA-1810-1 libapache-mod-jk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1810-1 libapache-mod-jk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-jk', release: '4.0', reference: '1.2.18-3etch2');
deb_check(prefix: 'libapache-mod-jk-doc', release: '4.0', reference: '1.2.18-3etch2');
deb_check(prefix: 'libapache2-mod-jk', release: '4.0', reference: '1.2.18-3etch2');
deb_check(prefix: 'libapache-mod-jk-doc', release: '5.0', reference: '1.2.26-2+lenny1');
deb_check(prefix: 'libapache2-mod-jk', release: '5.0', reference: '1.2.26-2+lenny1');
deb_check(prefix: 'libapache-mod-jk', release: '5.0', reference: '1.2.26-2+lenny1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
