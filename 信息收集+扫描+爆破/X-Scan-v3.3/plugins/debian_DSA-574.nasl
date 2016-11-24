# This script was automatically generated from the dsa-574
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15672);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "574");
 script_cve_id("CVE-2004-0916");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-574 security update');
 script_set_attribute(attribute: 'description', value:
'The upstream developers discovered a problem in cabextract, a tool to
extract cabinet files.  The program was able to overwrite files in
upper directories.  This could lead an attacker to overwrite arbitrary
files.
For the stable distribution (woody) this problem has been fixed in
version 0.2-2b.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-574');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cabextract package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA574] DSA-574-1 cabextract");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-574-1 cabextract");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cabextract', release: '3.0', reference: '0.2-2b');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
