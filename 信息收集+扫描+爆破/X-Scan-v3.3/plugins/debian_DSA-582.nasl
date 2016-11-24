# This script was automatically generated from the dsa-582
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15680);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "582");
 script_cve_id("CVE-2004-0989");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-582 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" discovered several buffer overflows in libxml and
libxml2, the XML C parser and toolkits for GNOME.  Missing boundary
checks could cause several buffers to be overflown, which may cause
the client to execute arbitrary code.
The following vulnerability matrix lists corrected versions of these
libraries:
For the stable distribution (woody) these problems have been fixed in
version 1.8.17-2woody2 of libxml and in version 2.4.19-4woody2 of
libxml2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-582');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libxml packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA582] DSA-582-1 libxml");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-582-1 libxml");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxml-dev', release: '3.0', reference: '1.8.17-2woody2');
deb_check(prefix: 'libxml1', release: '3.0', reference: '1.8.17-2woody2');
deb_check(prefix: 'libxml2', release: '3.0', reference: '2.4.19-4woody2');
deb_check(prefix: 'libxml2-dev', release: '3.0', reference: '2.4.19-4woody2');
deb_check(prefix: 'libxml', release: '3.0', reference: '1.8.17-2woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
