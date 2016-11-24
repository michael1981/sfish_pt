# This script was automatically generated from the dsa-057
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14894);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "057");
 script_cve_id("CVE-2001-0489");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-057 security update');
 script_set_attribute(attribute: 'description', value:
'The gftp package as distributed with Debian GNU/Linux 2.2 has a problem
in its logging code: it logged data received from the network but it did
not protect itself from printf format attacks. An attacker can use this
by making an FTP server return special responses that exploit this.

This has been fixed in version 2.0.6a-3.1, and we recommend that you
upgrade your gftp package.

Note: this advisory was posted as DSA-055-1 by mistake.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-057');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-057
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA057] DSA-057-1 gftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-057-1 gftp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gftp', release: '2.2', reference: '2.0.6a-3.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
