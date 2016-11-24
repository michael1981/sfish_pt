# This script was automatically generated from the dsa-350
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15187);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "350");
 script_cve_id("CVE-2003-0358");
 script_bugtraq_id(6806);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-350 security update');
 script_set_attribute(attribute: 'description', value:
'The falconseye package is vulnerable to a buffer overflow exploited
via a long -s command line option.  This vulnerability could be used
by an attacker to gain gid \'games\' on a system where falconseye is
installed.
Note that falconseye does not contain the file permission error
CVE-2003-0359 which affected some other nethack packages.
For the stable distribution (woody) this problem has been fixed in
version 1.9.3-7woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-350');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-350
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA350] DSA-350-1 falconseye");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-350-1 falconseye");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'falconseye', release: '3.0', reference: '1.9.3-7woody3');
deb_check(prefix: 'falconseye-data', release: '3.0', reference: '1.9.3-7woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
