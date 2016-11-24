# This script was automatically generated from the dsa-429
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15266);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "429");
 script_cve_id("CVE-2003-0971");
 script_bugtraq_id(9115);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-429 security update');
 script_set_attribute(attribute: 'description', value:
'Phong Nguyen identified a severe bug in the way GnuPG creates and uses
ElGamal keys for signing.  This is a significant security failure
which can lead to a compromise of almost all ElGamal keys used for
signing.
This update disables the use of this type of key.
For the current stable distribution (woody) this problem has been
fixed in version 1.0.6-4woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-429');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-429
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA429] DSA-429-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-429-1 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '3.0', reference: '1.0.6-4woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
