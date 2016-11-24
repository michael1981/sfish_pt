# This script was automatically generated from the dsa-804
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19611);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "804");
 script_cve_id("CVE-2005-1920");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-804 security update');
 script_set_attribute(attribute: 'description', value:
'KDE developers have reported a vulnerability in the backup file
handling of Kate and Kwrite.  The backup files are created with
default permissions, even if the original file had more strict
permissions set.  This could disclose information unintendedly.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-6.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-804');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdelibs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA804] DSA-804-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-804-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdelibs', release: '3.1', reference: '3.3.2-6.2');
deb_check(prefix: 'kdelibs-bin', release: '3.1', reference: '3.3.2-6.2');
deb_check(prefix: 'kdelibs-data', release: '3.1', reference: '3.3.2-6.2');
deb_check(prefix: 'kdelibs4', release: '3.1', reference: '3.3.2-6.2');
deb_check(prefix: 'kdelibs4-dev', release: '3.1', reference: '3.3.2-6.2');
deb_check(prefix: 'kdelibs4-doc', release: '3.1', reference: '3.3.2-6.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
