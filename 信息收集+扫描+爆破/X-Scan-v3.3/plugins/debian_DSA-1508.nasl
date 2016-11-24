# This script was automatically generated from the dsa-1508
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31169);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1508");
 script_cve_id("CVE-2008-0932");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1508 security update');
 script_set_attribute(attribute: 'description', value:
'Dan Dennison discovered that Diatheke, a CGI program to make a bible
website, performs insufficient sanitising of a parameter, allowing a
remote attacker to execute arbitrary shell commands as the web server
user.
For the old stable distribution (sarge), this problem has been fixed in
version 1.5.7-7sarge1.
For the stable distribution (etch), this problem has been fixed in version
1.5.9-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1508');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your diatheke package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1508] DSA-1508-1 diatheke");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1508-1 diatheke");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'diatheke', release: '3.1', reference: '1.5.7-7sarge1');
deb_check(prefix: 'libsword-dev', release: '3.1', reference: '1.5.7-7sarge1');
deb_check(prefix: 'libsword4', release: '3.1', reference: '1.5.7-7sarge1');
deb_check(prefix: 'diatheke', release: '4.0', reference: '1.5.9-2etch1');
deb_check(prefix: 'libsword-dev', release: '4.0', reference: '1.5.9-2etch1');
deb_check(prefix: 'libsword6', release: '4.0', reference: '1.5.9-2etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
