# This script was automatically generated from the dsa-622
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16087);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "622");
 script_cve_id("CVE-2004-1181");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-622 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernández-Sanguino Peña from the Debian Security Audit Project
has discovered multiple insecure uses
of temporary files that could lead to overwriting arbitrary files via
a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 21.8-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-622');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your htmlheadline package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA622] DSA-622-1 htmlheadline");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-622-1 htmlheadline");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'htmlheadline', release: '3.0', reference: '21.8-3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
