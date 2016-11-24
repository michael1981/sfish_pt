# This script was automatically generated from the dsa-338
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15175);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "338");
 script_cve_id("CVE-2003-0500");
 script_bugtraq_id(7974);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-338 security update');
 script_set_attribute(attribute: 'description', value:
'runlevel [runlevel@raregazz.org] reported that ProFTPD\'s PostgreSQL
authentication module is vulnerable to a SQL injection attack.  This
vulnerability could be exploited by a remote, unauthenticated attacker
to execute arbitrary SQL statements, potentially exposing the
passwords of other users, or to connect to ProFTPD as an arbitrary
user without supplying the correct password.
For the stable distribution (woody) this problem has been fixed in
version 1.2.4+1.2.5rc1-5woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-338');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-338
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA338] DSA-338-1 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-338-1 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2');
deb_check(prefix: 'proftpd-common', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2');
deb_check(prefix: 'proftpd-doc', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2');
deb_check(prefix: 'proftpd-ldap', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2');
deb_check(prefix: 'proftpd-mysql', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2');
deb_check(prefix: 'proftpd-pgsql', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
