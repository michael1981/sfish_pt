# This script was automatically generated from the dsa-688
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17196);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "688");
 script_cve_id("CVE-2005-0446");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-688 security update');
 script_set_attribute(attribute: 'description', value:
'Upstream developers have discovered several problems in squid, the
Internet object cache, the popular WWW proxy cache.  A remote attacker
can cause squid to crash via certain DNS responses.
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-688');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA688] DSA-688-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-688-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody7');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody7');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
