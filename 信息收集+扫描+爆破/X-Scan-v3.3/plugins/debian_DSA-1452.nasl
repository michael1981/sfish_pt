# This script was automatically generated from the dsa-1452
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29861);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1452");
 script_cve_id("CVE-2007-5300");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1452 security update');
 script_set_attribute(attribute: 'description', value:
'<q>k1tk4t</q> discovered that wzdftpd, a portable, modular, small and efficient
ftp server, did not correctly handle the receipt of long usernames.  This
could allow remote users to cause the daemon to exit.
For the old stable distribution (sarge), this problem has been fixed in
version 0.5.2-1.1sarge3.
For the stable distribution (etch), this problem has been fixed in version
0.8.1-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1452');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wzdftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1452] DSA-1452-1 wzdftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1452-1 wzdftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wzdftpd', release: '3.1', reference: '0.5.2-1.1sarge3');
deb_check(prefix: 'wzdftpd-back-mysql', release: '3.1', reference: '0.5.2-1.1sarge3');
deb_check(prefix: 'wzdftpd-dev', release: '3.1', reference: '0.5.2-1.1sarge3');
deb_check(prefix: 'wzdftpd-mod-perl', release: '3.1', reference: '0.5.2-1.1sarge3');
deb_check(prefix: 'wzdftpd-mod-tcl', release: '3.1', reference: '0.5.2-1.1sarge3');
deb_check(prefix: 'wzdftpd', release: '4.0', reference: '0.8.1-2etch1');
deb_check(prefix: 'wzdftpd-back-mysql', release: '4.0', reference: '0.8.1-2etch1');
deb_check(prefix: 'wzdftpd-back-pgsql', release: '4.0', reference: '0.8.1-2etch1');
deb_check(prefix: 'wzdftpd-dev', release: '4.0', reference: '0.8.1-2etch1');
deb_check(prefix: 'wzdftpd-mod-avahi', release: '4.0', reference: '0.8.1-2etch1');
deb_check(prefix: 'wzdftpd-mod-perl', release: '4.0', reference: '0.8.1-2etch1');
deb_check(prefix: 'wzdftpd-mod-tcl', release: '4.0', reference: '0.8.1-2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
