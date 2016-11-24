# This script was automatically generated from the dsa-011
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14848);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "011");
 script_cve_id("CVE-2001-0141");
 script_bugtraq_id(2187);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-011 security update');
 script_set_attribute(attribute: 'description', value:
' Immunix reports that mgetty does not create temporary
files in a secure manner, which could lead to a symlink attack. This has been
corrected in mgetty 1.1.21-3potato1

We recommend you upgrade your mgetty package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-011');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-011
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA011] DSA-011-2 mgetty");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-011-2 mgetty");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mgetty', release: '2.2', reference: '1.1.21-3potato1');
deb_check(prefix: 'mgetty-docs', release: '2.2', reference: '1.1.21-3potato1');
deb_check(prefix: 'mgetty-fax', release: '2.2', reference: '1.1.21-3potato1');
deb_check(prefix: 'mgetty-viewfax', release: '2.2', reference: '1.1.21-3potato1');
deb_check(prefix: 'mgetty-voice', release: '2.2', reference: '1.1.21-3potato1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
