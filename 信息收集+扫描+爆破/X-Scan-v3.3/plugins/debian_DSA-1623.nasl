# This script was automatically generated from the dsa-1623
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33772);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1623");
 script_cve_id("CVE-2008-1447");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1623 security update');
 script_set_attribute(attribute: 'description', value:
'Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks. Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting.
This update changes Debian\'s dnsmasq packages to implement the
recommended countermeasure: UDP query source port randomization. This
change increases the size of the space from which an attacker has to
guess values in a backwards-compatible fashion and makes successful
attacks significantly more difficult.
This update also switches the random number generator to Dan
Bernstein\'s SURF.
For the stable distribution (etch), this problem has been fixed in
version 2.35-1+etch4. Packages for alpha will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1623');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dnsmasq package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1623] DSA-1623-1 dnsmasq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1623-1 dnsmasq");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dnsmasq', release: '4.0', reference: '2.35-1+etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
