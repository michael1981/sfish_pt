# This script was automatically generated from the dsa-990
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22856);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "990");
 script_cve_id("CVE-2006-0670");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-990 security update');
 script_set_attribute(attribute: 'description', value:
'A denial of service condition has been discovered in bluez-hcidump, a
utility that analyses Bluetooth HCI packets, which can be triggered
remotely.
The old stable distribution (woody) does not contain bluez-hcidump packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.17-1sarge1
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-990');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bluez-hcidump package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA990] DSA-990-1 bluez-hcidump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-990-1 bluez-hcidump");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bluez-hcidump', release: '3.1', reference: '1.17-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
