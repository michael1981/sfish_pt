# This script was automatically generated from the dsa-583
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15681);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "583");
 script_cve_id("CVE-2004-0972");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-583 security update');
 script_set_attribute(attribute: 'description', value:
'Trustix developers discovered insecure temporary file creation in a
supplemental script in the lvm10 package that didn\'t check for
existing temporary directories, allowing local users to overwrite
files via a symlink attack.
For the stable distribution (woody) this problem has been fixed in
version 1.0.4-5woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-583');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lvm10 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA583] DSA-583-1 lvm10");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-583-1 lvm10");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lvm10', release: '3.0', reference: '1.0.4-5woody2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
