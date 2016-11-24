# This script was automatically generated from the dsa-703
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17674);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "703");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");
 script_xref(name: "CERT", value: "291924");
 script_xref(name: "CERT", value: "341908");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-703 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in telnet clients that could be
exploited by malicious daemons the client connects to.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Gaël Delalleau discovered a buffer overflow in the env_opt_add()
    function that allow a remote attacker to execute arbitrary code.
    Gaël Delalleau discovered a buffer overflow in the handling of the
    LINEMODE suboptions in telnet clients.  This can lead to the
    execution of arbitrary code when connected to a malicious server.
For the stable distribution (woody) these problems have been fixed in
version 1.2.4-5woody8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-703');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your krb5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA703] DSA-703-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-703-1 krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody8');
deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
