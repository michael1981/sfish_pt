# This script was automatically generated from the dsa-844
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19848);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "844");
 script_cve_id("CVE-2005-2963");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-844 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability in mod_auth_shadow, an Apache module that lets users
perform HTTP authentication against /etc/shadow, has been discovered.
The module runs for all locations that use the \'require group\'
directive which would bypass access restrictions controlled by another
authorisation mechanism, such as AuthGroupFile file, if the username
is listed in the password file and in the gshadow file in the proper
group and the supplied password matches against the one in the shadow
file.
This update requires an explicit "AuthShadow on" statement if website
authentication should be checked against /etc/shadow.
For the old stable distribution (woody) this problem has been fixed in
version 1.3-3.1woody.2.
For the stable distribution (sarge) this problem has been fixed in
version 1.4-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-844');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-auth-shadow package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA844] DSA-844-1 mod-auth-shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-844-1 mod-auth-shadow");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody.2');
deb_check(prefix: 'libapache-mod-auth-shadow', release: '3.1', reference: '1.4-1sarge1');
deb_check(prefix: 'mod-auth-shadow', release: '3.1', reference: '1.4-1sarge1');
deb_check(prefix: 'mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
