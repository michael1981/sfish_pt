# This script was automatically generated from the dsa-353
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15190);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "353");
 script_cve_id("CVE-2003-0606");
 script_bugtraq_id(6150);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-353 security update');
 script_set_attribute(attribute: 'description', value:
'sup, a package used to maintain collections of files in identical
versions across machines, fails to take appropriate security
precautions when creating temporary files.  A local attacker could
exploit this vulnerability to overwrite arbitrary files with the
privileges of the user running sup.
For the stable distribution (woody) this problem has been fixed in
version 1.8-8woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-353');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-353
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA353] DSA-353-1 sup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-353-1 sup");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sup', release: '3.0', reference: '1.8-8woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
