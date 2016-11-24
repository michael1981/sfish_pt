# This script was automatically generated from the dsa-1411
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(28300);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1411");
 script_cve_id("CVE-2007-5162", "CVE-2007-5770");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1411 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Ruby, an object-oriented
scripting language. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2007-5162
    It was discovered that the Ruby HTTP(S) module performs insufficient
    validation of SSL certificates, which may lead to man-in-the-middle
    attacks.
CVE-2007-5770
    It was discovered that the Ruby modules for FTP, Telnet, IMAP, POP
    and SMTP perform insufficient validation of SSL certificates, which
    may lead to man-in-the-middle attacks.
For the old stable distribution (sarge) these problems have been fixed
in version 0.1.4a-1sarge1. Packages for sparc will be provided later.
The stable distribution (etch) no longer contains libopenssl-ruby.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1411');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libopenssl-ruby packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1411] DSA-1411-1 libopenssl-ruby");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1411-1 libopenssl-ruby");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libopenssl-ruby1.6', release: '3.1', reference: '0.1.4a-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
