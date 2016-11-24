# This script was automatically generated from the dsa-214
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15051);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "214");
 script_cve_id("CVE-2002-1306");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-214 security update');
 script_set_attribute(attribute: 'description', value:
'Olaf Kirch from SuSE Linux AG discovered another vulnerability in the
klisa package, that provides a LAN information service similar to
"Network Neighbourhood".  The lisa daemon contains a buffer overflow
vulnerability which potentially enables any local user, as well as
any remote attacker on the LAN who is able to gain control of the LISa
port (7741 by default), to obtain root privileges.  In addition, a
remote attacker potentially may be able to gain access to a victim\'s
account by using an "rlan://" URL in an HTML page or via another KDE
application.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-214');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your klisa package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA214] DSA-214-1 kdenetwork");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-214-1 kdenetwork");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdict', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'kit', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'klisa', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'kmail', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'knewsticker', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'knode', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'korn', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'kppp', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'ksirc', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'ktalkd', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'libkdenetwork1', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'libmimelib-dev', release: '3.0', reference: '2.2.2-14.5');
deb_check(prefix: 'libmimelib1', release: '3.0', reference: '2.2.2-14.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
