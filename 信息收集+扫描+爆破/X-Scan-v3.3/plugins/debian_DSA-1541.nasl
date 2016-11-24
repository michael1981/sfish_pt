# This script was automatically generated from the dsa-1541
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31811);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1541");
 script_cve_id("CVE-2007-5707", "CVE-2007-5708", "CVE-2007-6698", "CVE-2008-0658");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1541 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in OpenLDAP, a
free implementation of the Lightweight Directory Access Protocol. The
Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2007-5707
    Thomas Sesselmann discovered that slapd could be crashed by a
    malformed modify requests.
CVE-2007-5708
    Toby Blade discovered that incorrect memory handling in slapo-pcache
    could lead to denial of service through crafted search requests.
CVE-2007-6698
    It was discovered that a programming error in the interface to the
    BDB storage backend could lead to denial of service through
    crafted modify requests.
CVE-2008-0658
    It was discovered that a programming error in the interface to the
    BDB storage backend could lead to denial of service through
    crafted modrdn requests.
For the stable distribution (etch), these problems have been fixed in
version 2.3.30-5+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1541');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openldap2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1541] DSA-1541-1 openldap2.3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1541-1 openldap2.3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ldap-utils', release: '4.0', reference: '2.3.30-5+etch1');
deb_check(prefix: 'libldap-2.3-0', release: '4.0', reference: '2.3.30-5+etch1');
deb_check(prefix: 'slapd', release: '4.0', reference: '2.3.30-5+etch1');
deb_check(prefix: 'openldap2.3', release: '4.0', reference: '2.3.30-5+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
