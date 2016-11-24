# This script was automatically generated from the dsa-526
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15363);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "526");
 script_cve_id("CVE-2004-0582", "CVE-2004-0583");
 script_bugtraq_id(10474);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-526 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in webmin:
CVE-2004-0582: Unknown vulnerability in Webmin 1.140 allows remote
 attackers to bypass access control rules and gain read access to
 configuration information for a module.
CVE-2004-0583: The account lockout functionality in (1) Webmin 1.140
 and (2) Usermin 1.070 does not parse certain character strings, which
 allows remote attackers to conduct a brute force attack to guess user
 IDs and passwords.
For the current stable distribution (woody), these problems have been
fixed in version 0.94-7woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-526');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-526
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA526] DSA-526-1 webmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-526-1 webmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webmin', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-apache', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-bind8', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-burner', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-cluster-software', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-cluster-useradmin', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-core', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-cpan', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-dhcpd', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-exports', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-fetchmail', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-grub', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-heartbeat', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-inetd', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-jabber', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-lpadmin', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-mon', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-mysql', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-nis', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-postfix', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-postgresql', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-ppp', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-qmailadmin', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-quota', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-raid', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-samba', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-sendmail', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-software', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-squid', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-sshd', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-ssl', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-status', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-stunnel', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-wuftpd', release: '3.0', reference: '0.94-7woody2');
deb_check(prefix: 'webmin-xinetd', release: '3.0', reference: '0.94-7woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
