# This script was automatically generated from the dsa-771
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19336);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "771");
 script_cve_id("CVE-2005-2301", "CVE-2005-2302");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-771 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in pdns, a versatile nameserver
that can lead to a denial of service.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Norbert Sendetzky and Jan de Groot discovered that the LDAP backend
    did not properly escape all queries, allowing it to fail and not
    answer queries anymore.
    Wilco Baan discovered that queries from clients without recursion
    permission can temporarily blank out domains to clients with
    recursion permitted.  This enables outside users to blank out a
    domain temporarily to normal users.
The old stable distribution (woody) does not contain pdns packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.9.17-13sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-771');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pdns package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA771] DSA-771-1 pdns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-771-1 pdns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'pdns', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-backend-geo', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-backend-ldap', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-backend-mysql', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-backend-pgsql', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-backend-pipe', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-backend-sqlite', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-doc', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-recursor', release: '3.1', reference: '2.9.17-13sarge1');
deb_check(prefix: 'pdns-server', release: '3.1', reference: '2.9.17-13sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
