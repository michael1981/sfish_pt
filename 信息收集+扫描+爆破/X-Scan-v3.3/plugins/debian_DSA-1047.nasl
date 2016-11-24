# This script was automatically generated from the dsa-1047
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22589);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1047");
 script_cve_id("CVE-2006-2147");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1047 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in resmgr, a resource manager library
daemon and PAM module, that allows local users to bypass access
control rules and open any USB device when access to one device was
granted.
The old stable distribution (woody) does not contain resmgr packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0-2sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1047');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your resmgr package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1047] DSA-1047-1 resmgr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1047-1 resmgr");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libresmgr-dev', release: '3.1', reference: '1.0-2sarge2');
deb_check(prefix: 'libresmgr1', release: '3.1', reference: '1.0-2sarge2');
deb_check(prefix: 'resmgr', release: '3.1', reference: '1.0-2sarge2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
