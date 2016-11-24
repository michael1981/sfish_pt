# This script was automatically generated from the dsa-1801
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38833);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1801");
 script_cve_id("CVE-2009-0159", "CVE-2009-1252");
 script_xref(name: "CERT", value: "853097");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1801 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in NTP, the Network
Time Protocol reference implementation. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2009-0159
    A buffer overflow in ntpq allow a remote NTP server to create a
    denial of service attack or to execute arbitrary code via a crafted
    response.
CVE-2009-1252
    A buffer overflow in ntpd allows a remote attacker to create a
    denial of service attack or to execute arbitrary code when the
    autokey functionality is enabled.
For the old stable distribution (etch), these problems have been fixed in
version 4.2.2.p4+dfsg-2etch3.
For the stable distribution (lenny), these problems have been fixed in
version 4.2.4p4+dfsg-8lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1801');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ntp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1801] DSA-1801-1 ntp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1801-1 ntp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ntp', release: '4.0', reference: '4.2.2.p4+dfsg-2etch3');
deb_check(prefix: 'ntp-doc', release: '4.0', reference: '4.2.2.p4+dfsg-2etch3');
deb_check(prefix: 'ntp-refclock', release: '4.0', reference: '4.2.2.p4+dfsg-2etch3');
deb_check(prefix: 'ntp-simple', release: '4.0', reference: '4.2.2.p4+dfsg-2etch3');
deb_check(prefix: 'ntpdate', release: '4.0', reference: '4.2.2.p4+dfsg-2etch3');
deb_check(prefix: 'ntp', release: '5.0', reference: '4.2.4p4+dfsg-8lenny2');
deb_check(prefix: 'ntp-doc', release: '5.0', reference: '4.2.4p4+dfsg-8lenny2');
deb_check(prefix: 'ntpdate', release: '5.0', reference: '4.2.4p4+dfsg-8lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
