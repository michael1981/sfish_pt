# This script was automatically generated from the dsa-035
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14872);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "035");
 script_cve_id("CVE-2001-0457");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-035 security update');
 script_set_attribute(attribute: 'description', value:
'It has been reported that one can tweak man2html remotely
into consuming all available memory.  This has been fixed by Nicolás Lichtmaier
with help of Stephan Kulow.

<P>We recommend you upgrade your man2html package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-035');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-035
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA035] DSA-035-1 man2html");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-035-1 man2html");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'man2html', release: '2.2', reference: '1.5-23');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
