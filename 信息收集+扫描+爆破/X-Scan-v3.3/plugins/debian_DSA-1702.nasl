# This script was automatically generated from the dsa-1702
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35365);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1702");
 script_cve_id("CVE-2009-0021");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1702 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that NTP, an implementation of the Network Time
Protocol, does not properly check the result of an OpenSSL function
for verifying cryptographic signatures, which may ultimately lead to
the acceptance of unauthenticated time information.  (Note that
cryptographic authentication of time servers is often not enabled in
the first place.)
For the stable distribution (etch), this problem has been fixed in
version 4.2.2.p4+dfsg-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1702');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ntp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1702] DSA-1702-1 ntp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1702-1 ntp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ntp', release: '4.0', reference: '4.2.2.p4+dfsg-2etch1');
deb_check(prefix: 'ntp-doc', release: '4.0', reference: '4.2.2.p4+dfsg-2etch1');
deb_check(prefix: 'ntp-refclock', release: '4.0', reference: '4.2.2.p4+dfsg-2etch1');
deb_check(prefix: 'ntp-simple', release: '4.0', reference: '4.2.2.p4+dfsg-2etch1');
deb_check(prefix: 'ntpdate', release: '4.0', reference: '4.2.2.p4+dfsg-2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
