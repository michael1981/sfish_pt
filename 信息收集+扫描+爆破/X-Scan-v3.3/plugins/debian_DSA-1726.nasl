# This script was automatically generated from the dsa-1726
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35738);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1726");
 script_cve_id("CVE-2009-0544");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1726 security update');
 script_set_attribute(attribute: 'description', value:
'Mike Wiacek discovered that a buffer overflow in the ARC2 implementation
of Python Crypto, a collection of cryptographic algorithms and protocols
for Python allows denial of service and potentially the execution of
arbitrary code.
For the stable distribution (lenny), this problem has been fixed in
version 2.0.1+dfsg1-2.3+lenny0.
Due to a technical limitation in the Debian archive management scripts
the update for the old stable distribution (etch) cannot be released
synchronously. It will be fixed in version 2.0.1+dfsg1-1.2+etch0 soon.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1726');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your python-crypto package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1726] DSA-1726-1 python-crypto");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1726-1 python-crypto");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-crypto', release: '5.0', reference: '2.0.1+dfsg1-2.3+lenny0');
deb_check(prefix: 'python-crypto-dbg', release: '5.0', reference: '2.0.1+dfsg1-2.3+lenny0');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
