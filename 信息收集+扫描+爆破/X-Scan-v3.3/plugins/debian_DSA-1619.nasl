# This script was automatically generated from the dsa-1619
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33739);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1619");
 script_cve_id("CVE-2008-1447", "CVE-2008-4099");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1619 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple weaknesses have been identified in PyDNS, a DNS client
implementation for the Python language.  Dan Kaminsky identified a
practical vector of DNS response spoofing and cache poisoning,
exploiting the limited entropy in a DNS transaction ID and lack of
UDP source port randomization in many DNS implementations.  Scott
Kitterman noted that python-dns is vulnerable to this predictability,
as it randomizes neither its transaction ID nor its source port.
Taken together, this lack of entropy leaves applications using
python-dns to perform DNS queries highly susceptible to response
forgery.
The Common Vulnerabilities and Exposures project identifies this
class of weakness as CVE-2008-1447
and this specific instance in PyDNS as CVE-2008-4099.
For the stable distribution (etch), these problems have been fixed in
version 2.3.0-5.2+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1619');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your python-dns package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1619] DSA-1619-1 python-dns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1619-1 python-dns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-dns', release: '4.0', reference: '2.3.0-5.2+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
