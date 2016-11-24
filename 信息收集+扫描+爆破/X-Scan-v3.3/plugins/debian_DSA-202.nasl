# This script was automatically generated from the dsa-202
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15039);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "202");
 script_cve_id("CVE-2002-1395");
 script_bugtraq_id(6307);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-202 security update');
 script_set_attribute(attribute: 'description', value:
'Tatsuya Kinoshita discovered that IM, which contains interface
commands and Perl libraries for E-mail and NetNews, creates temporary
files insecurely.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-202');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your IM package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA202] DSA-202-1 im");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-202-1 im");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'im', release: '2.2', reference: '133-2.3');
deb_check(prefix: 'im', release: '3.0', reference: '141-18.2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
