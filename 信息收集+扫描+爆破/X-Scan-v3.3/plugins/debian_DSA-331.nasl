# This script was automatically generated from the dsa-331
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15168);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "331");
 script_cve_id("CVE-2003-0455");
 script_bugtraq_id(8057);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-331 security update');
 script_set_attribute(attribute: 'description', value:
'imagemagick\'s libmagick library, under certain circumstances, creates
temporary files without taking appropriate security precautions.  This
vulnerability could be exploited by a local user to create or
overwrite files with the privileges of another user who is invoking a
program using this library.
For the stable distribution (woody) this problem has been fixed in
version 4:5.4.4.5-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-331');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-331
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA331] DSA-331-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-331-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody1');
deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody1');
deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody1');
deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
