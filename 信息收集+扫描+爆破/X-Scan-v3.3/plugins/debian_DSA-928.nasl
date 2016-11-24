# This script was automatically generated from the dsa-928
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22794);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "928");
 script_cve_id("CVE-2005-3341");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-928 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that two scripts in the dhis-tools-dns package, DNS
configuration utilities for a dynamic host information System, which
are usually executed by root, create temporary files in an insecure
fashion.
The old stable distribution (woody) does not contain a dhis-tools-dns
package.
For the stable distribution (sarge) these problems have been fixed in
version 5.0-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-928');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dhis-tools-dns package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA928] DSA-928-1 dhis-tools-dns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-928-1 dhis-tools-dns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dhis-tools-dns', release: '3.1', reference: '5.0-3sarge1');
deb_check(prefix: 'dhis-tools-genkeys', release: '3.1', reference: '5.0-3sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
