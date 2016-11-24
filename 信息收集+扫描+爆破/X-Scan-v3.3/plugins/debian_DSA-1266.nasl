# This script was automatically generated from the dsa-1266
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24819);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1266");
 script_cve_id("CVE-2007-1263");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1266 security update');
 script_set_attribute(attribute: 'description', value:
'Gerardo Richarte discovered that GnuPG, a free PGP replacement, provides
insufficient user feedback if an OpenPGP message contains both unsigned
and signed portions. Inserting text segments into an otherwise signed
message could be exploited to forge the content of signed messages.
This update prevents such attacks; the old behaviour can still be
activated by passing the --allow-multiple-messages option.
For the stable distribution (sarge) these problems have been fixed in
version 1.4.1-1.sarge7.
For the upcoming stable distribution (etch) these problems have been
fixed in version 1.4.6-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1266');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnupg packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1266] DSA-1266-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1266-1 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge7');
deb_check(prefix: 'gnupg', release: '4.0', reference: '1.4.6-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
