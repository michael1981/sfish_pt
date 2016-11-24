# This script was automatically generated from the dsa-1786
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38667);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1786");
 script_cve_id("CVE-2009-0798");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1786 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that acpid, a daemon for delivering ACPI events, is
prone to a denial of service attack by opening a large number of UNIX
sockets, which are not closed properly.
For the stable distribution (lenny), this problem has been fixed in
version 1.0.8-1lenny1.
For the oldstable distribution (etch), this problem has been fixed in
version 1.0.4-5etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1786');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your acpid packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1786] DSA-1786-1 acpid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1786-1 acpid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'acpid', release: '4.0', reference: '1.0.4-5etch1');
deb_check(prefix: 'acpid', release: '5.0', reference: '1.0.8-1lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
