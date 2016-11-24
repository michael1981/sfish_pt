# This script was automatically generated from the dsa-689
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17197);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "689");
 script_cve_id("CVE-2005-0088");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-689 security update');
 script_set_attribute(attribute: 'description', value:
'Graham Dumpleton discovered a flaw which can affect anyone using the
publisher handle of the Apache Software Foundation\'s mod_python.  The
publisher handle lets you publish objects inside modules to make them
callable via URL.  The flaw allows a carefully crafted URL to obtain
extra information that should not be visible (information leak).
For the stable distribution (woody) this problem has been fixed in
version 2.7.8-0.0woody5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-689');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-python package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA689] DSA-689-1 libapache-mod-python");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-689-1 libapache-mod-python");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-python', release: '3.0', reference: '2.7.8-0.0woody5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
