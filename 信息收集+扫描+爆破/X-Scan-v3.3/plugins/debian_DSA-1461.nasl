# This script was automatically generated from the dsa-1461
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29938);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1461");
 script_cve_id("CVE-2007-6284");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1461 security update');
 script_set_attribute(attribute: 'description', value:
'Brad Fitzpatrick discovered that the UTF-8 decoding functions of libxml2,
the GNOME XML library, validate UTF-8 correctness insufficiently, which
may lead to denial of service by forcing libxml2 into an infinite loop.


For the old stable distribution (sarge), this problem has been fixed in
version 2.6.16-7sarge1.


For the stable distribution (etch), this problem has been fixed in
version 2.6.27.dfsg-2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1461');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libxml2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1461] DSA-1461-1 libxml2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1461-1 libxml2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxml2', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'libxml2-dev', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'libxml2-doc', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'libxml2-python2.3', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'libxml2-utils', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'python-libxml2', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'python2.2-libxml2', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'python2.3-libxml2', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'python2.4-libxml2', release: '3.1', reference: '2.6.16-7sarge1');
deb_check(prefix: 'libxml2', release: '4.0', reference: '2.6.27.dfsg-2');
deb_check(prefix: 'libxml2-dbg', release: '4.0', reference: '2.6.27.dfsg-2');
deb_check(prefix: 'libxml2-dev', release: '4.0', reference: '2.6.27.dfsg-2');
deb_check(prefix: 'libxml2-doc', release: '4.0', reference: '2.6.27.dfsg-2');
deb_check(prefix: 'libxml2-utils', release: '4.0', reference: '2.6.27.dfsg-2');
deb_check(prefix: 'python-libxml2', release: '4.0', reference: '2.6.27.dfsg-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
