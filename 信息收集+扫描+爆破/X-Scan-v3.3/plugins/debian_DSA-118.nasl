# This script was automatically generated from the dsa-118
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14955);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "118");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-118 security update');
 script_set_attribute(attribute: 'description', value:
'Tim Waugh found several insecure uses of temporary files in the xsane
program, which is used for scanning.  This was fixed for Debian/stable
by moving those files into a securely created directory within the
/tmp directory.
This problem has been fixed in version 0.50-5.1 for the stable Debian
distribution and in version 0.84-0.1 for the testing and unstable
distribution of Debian.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-118');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xsane package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA118] DSA-118-1 xsane");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-118-1 xsane");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xsane', release: '2.2', reference: '0.50-5.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
