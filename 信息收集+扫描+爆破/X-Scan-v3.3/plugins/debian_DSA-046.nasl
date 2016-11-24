# This script was automatically generated from the dsa-046
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14883);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "046");
 script_cve_id("CVE-2001-0430");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-046 security update');
 script_set_attribute(attribute: 'description', value:
'Colin Phipps discovered that the exuberant-ctags packages as distributed
with Debian GNU/Linux 2.2 creates temporary files insecurely. This has
been fixed in version 1:3.2.4-0.1 of the Debian package, and upstream
version 3.5.

Note: DSA-046-1 included an incorrectly compiled sparc package, which
the second edition fixed.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-046');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-046
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA046] DSA-046-2 exuberant-ctags");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-046-2 exuberant-ctags");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exuberant-ctags', release: '2.2', reference: '3.2.4-0.1.1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
