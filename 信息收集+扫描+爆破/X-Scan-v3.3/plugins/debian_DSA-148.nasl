# This script was automatically generated from the dsa-148
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14985);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "148");
 script_cve_id("CVE-2001-1034", "CVE-2002-1049", "CVE-2002-1050");
 script_bugtraq_id(3357, 5348, 5349);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-148 security update');
 script_set_attribute(attribute: 'description', value:
'A set of problems have been discovered in Hylafax, a flexible
client/server fax software distributed with many GNU/Linux
distributions.  Quoting SecurityFocus the problems are in detail:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-148');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hylafax packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA148] DSA-148-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-148-1 hylafax");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hylafax-client', release: '2.2', reference: '4.0.2-14.3');
deb_check(prefix: 'hylafax-doc', release: '2.2', reference: '4.0.2-14.3');
deb_check(prefix: 'hylafax-server', release: '2.2', reference: '4.0.2-14.3');
deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-1.1');
deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-1.1');
deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
