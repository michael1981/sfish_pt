# This script was automatically generated from the dsa-193
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15030);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "193");
 script_cve_id("CVE-2002-1247");
 script_bugtraq_id(6157);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-193 security update');
 script_set_attribute(attribute: 'description', value:
'iDEFENSE reports a security vulnerability in the klisa package, that
provides a LAN information service similar to "Network Neighbourhood",
which was discovered by Texonet.  It is possible for a local attacker
to exploit a buffer overflow condition in resLISa, a restricted
version of KLISa.  The vulnerability exists in the parsing of the
LOGNAME environment variable, an overly long value will overwrite the
instruction pointer thereby allowing an attacker to seize control of
the executable.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-193');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your klisa package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA193] DSA-193-1 kdenetwork");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-193-1 kdenetwork");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdict', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'kit', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'klisa', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'kmail', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'knewsticker', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'knode', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'korn', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'kppp', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'ksirc', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'ktalkd', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'libkdenetwork1', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'libmimelib-dev', release: '3.0', reference: '2.2.2-14.2');
deb_check(prefix: 'libmimelib1', release: '3.0', reference: '2.2.2-14.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
