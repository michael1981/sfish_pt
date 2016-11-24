# This script was automatically generated from the dsa-1465
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30000);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1465");
 script_cve_id("CVE-2008-0302");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1465 security update');
 script_set_attribute(attribute: 'description', value:
'Felipe Sateler discovered that apt-listchanges, a package change history
notification tool, used unsafe paths when importing its python libraries.
This could allow the execution of arbitrary shell commands if the root user
executed the command in a directory which other local users may write
to.
For the old stable distribution (sarge), this problem was not present.
For the stable distribution (etch), this problem has been fixed in version
2.72.5etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1465');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apt-listchanges package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1465] DSA-1465-2 apt-listchanges");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1465-2 apt-listchanges");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apt-listchanges', release: '4.0', reference: '2.72.5etch2');
deb_check(prefix: 'apt-listchanges', release: '4.0', reference: '2.72.5etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
