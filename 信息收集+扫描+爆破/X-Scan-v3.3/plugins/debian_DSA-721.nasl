# This script was automatically generated from the dsa-721
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18242);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "721");
 script_cve_id("CVE-2005-1345");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-721 security update');
 script_set_attribute(attribute: 'description', value:
'Michael Bhola discovered a bug in Squid, the popular WWW proxy cache.
Squid does not trigger a fatal error when it identifies missing or
invalid ACLs in the http_access configuration, which could lead to
less restrictive ACLs than intended by the administrator.
For the stable distribution (woody) this problem has been fixed in
version 2.4.6-2woody8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-721');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA721] DSA-721-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-721-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody8');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody8');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
