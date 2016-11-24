# This script was automatically generated from the dsa-1690
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35253);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1690");
 script_cve_id("CVE-2007-3372", "CVE-2008-5081");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1690 security update');
 script_set_attribute(attribute: 'description', value:
'Two denial of service conditions were discovered in avahi, a Multicast
DNS implementation.
Huge Dias discovered that the avahi daemon aborts with an assert error
if it encounters a UDP packet with source port 0 (CVE-2008-5081).
It was discovered that the avahi daemon aborts with an assert error if
it receives an empty TXT record over D-Bus (CVE-2007-3372).
For the stable distribution (etch), these problems have been fixed in
version 0.6.16-3etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1690');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your avahi packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1690] DSA-1690-1 avahi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1690-1 avahi");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'avahi-autoipd', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'avahi-daemon', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'avahi-discover', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'avahi-dnsconfd', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'avahi-utils', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-client-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-client3', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-common-data', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-common-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-common3', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-compat-howl-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-compat-howl0', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-compat-libdnssd-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-compat-libdnssd1', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-core-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-core4', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-glib-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-glib1', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-qt3-1', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-qt3-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-qt4-1', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'libavahi-qt4-dev', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'python-avahi', release: '4.0', reference: '0.6.16-3etch2');
deb_check(prefix: 'avahi', release: '4.0', reference: '0.6.16-3etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
