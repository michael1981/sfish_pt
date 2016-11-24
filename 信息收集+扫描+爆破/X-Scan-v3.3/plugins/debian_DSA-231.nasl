# This script was automatically generated from the dsa-231
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15068);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "231");
 script_cve_id("CVE-2003-0026");
 script_xref(name: "CERT", value: "284857");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-231 security update');
 script_set_attribute(attribute: 'description', value:
'The Internet Software Consortium discovered several vulnerabilities
during an audit of the ISC DHCP Daemon.  The vulnerabilities exist in
error handling routines within the minires library and may be
exploitable as stack overflows.  This could allow a remote attacker to
execute arbitrary code under the user id the dhcpd runs under, usually
root.  Other DHCP servers than dhcp3 doesn\'t seem to be affected.
For the stable distribution (woody) this problem has been
fixed in version 3.0+3.0.1rc9-2.1.
The old stable distribution (potato) does not contain dhcp3 packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-231');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dhcp3-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA231] DSA-231-1 dhcp3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-231-1 dhcp3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dhcp3-client', release: '3.0', reference: '3.0+3.0.1rc9-2.1');
deb_check(prefix: 'dhcp3-common', release: '3.0', reference: '3.0+3.0.1rc9-2.1');
deb_check(prefix: 'dhcp3-dev', release: '3.0', reference: '3.0+3.0.1rc9-2.1');
deb_check(prefix: 'dhcp3-relay', release: '3.0', reference: '3.0+3.0.1rc9-2.1');
deb_check(prefix: 'dhcp3-server', release: '3.0', reference: '3.0+3.0.1rc9-2.1');
deb_check(prefix: 'dhcp3', release: '3.0', reference: '3.0+3.0.1rc9-2.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
