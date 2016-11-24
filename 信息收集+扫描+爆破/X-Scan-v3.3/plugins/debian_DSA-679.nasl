# This script was automatically generated from the dsa-679
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16383);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "679");
 script_cve_id("CVE-2005-0159");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-679 security update');
 script_set_attribute(attribute: 'description', value:
'Sean Finney discovered several insecure temporary file uses in
toolchain-source, the GNU binutils and GCC source code and scripts.
These bugs can lead a local attacker with minimal knowledge to trick
the admin into overwriting arbitrary files via a symlink attack.  The
problems exist inside the Debian-specific tpkg-* scripts.
For the stable distribution (woody) these problems have been fixed in
version 3.0.4-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-679');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your toolchain-source package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA679] DSA-679-1 toolchain-source");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-679-1 toolchain-source");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'toolchain-source', release: '3.0', reference: '3.0.4-1woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
