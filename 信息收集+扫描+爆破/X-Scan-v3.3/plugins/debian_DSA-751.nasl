# This script was automatically generated from the dsa-751
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18667);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "751");
 script_cve_id("CVE-2005-1519");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-751 security update');
 script_set_attribute(attribute: 'description', value:
'The upstream developers have discovered a bug in the DNS lookup code
of Squid, the popular WWW proxy cache.  When the DNS client UDP port
(assigned by the operating system at startup) is unfiltered and the
network is not protected from IP spoofing, malicious users can spoof
DNS lookups which could result in users being redirected to arbitrary
web sites.
For the old stable distribution (woody) this problem has been fixed in
version 2.4.6-2woody9.
For the stable distribution (sarge) this problem has already been
fixed in version 2.5.9-9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-751');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA751] DSA-751-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-751-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody9');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody9');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody9');
deb_check(prefix: 'squid', release: '3.1', reference: '2.5.9-9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
