# This script was automatically generated from the dsa-1806
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38880);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1806");
 script_cve_id("CVE-2009-0148");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1806 security update');
 script_set_attribute(attribute: 'description', value:
'Matt Murphy discovered that cscope, a source code browsing tool, does not
verify the length of file names sourced in include statements, which may
potentially lead to the execution of arbitrary code through specially
crafted source code files.
For the stable distribution (lenny), this problem has been fixed in
version 15.6-6+lenny1.
Due to a technical limitation in the Debian archive management scripts
the update for the old stable distribution (etch) cannot be released
synchronously. It will be fixed in version 15.6-2+etch1 soon.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1806');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cscope package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1806] DSA-1806-1 cscope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1806-1 cscope");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cscope', release: '5.0', reference: '15.6-6+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
