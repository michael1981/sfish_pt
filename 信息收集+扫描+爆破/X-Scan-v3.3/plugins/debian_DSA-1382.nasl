# This script was automatically generated from the dsa-1382
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26975);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1382");
 script_cve_id("CVE-2007-4826");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1382 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that BGP peers can trigger a NULL pointer dereference
in the BGP daemon if debug logging is enabled, causing the BGP daemon to
crash.
For the old stable distribution (sarge), this problem has been fixed in
version 0.98.3-7.5.
For the stable distribution (etch), this problem has been fixed in
version 0.99.5-5etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1382');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your quagga packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1382] DSA-1382-1 quagga");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1382-1 quagga");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'quagga', release: '3.1', reference: '0.98.3-7.5');
deb_check(prefix: 'quagga-doc', release: '3.1', reference: '0.98.3-7.5');
deb_check(prefix: 'quagga', release: '4.0', reference: '0.99.5-5etch3');
deb_check(prefix: 'quagga-doc', release: '4.0', reference: '0.99.5-5etch3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
