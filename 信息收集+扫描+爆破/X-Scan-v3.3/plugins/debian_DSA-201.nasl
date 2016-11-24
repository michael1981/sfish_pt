# This script was automatically generated from the dsa-201
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15038);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "201");
 script_cve_id("CVE-2002-0666");
 script_xref(name: "CERT", value: "459371");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-201 security update');
 script_set_attribute(attribute: 'description', value:
'Bindview discovered a problem in several IPSEC implementations that do
not properly handle certain very short packets.  IPSEC is a set of
security extensions to IP which provide authentication and encryption.
Free/SWan in Debian is affected by this and is said to cause a kernel
panic.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-201');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freeswan package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA201] DSA-201-1 freeswan");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-201-1 freeswan");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freeswan', release: '3.0', reference: '1.96-1.4');
deb_check(prefix: 'kernel-patch-freeswan', release: '3.0', reference: '1.96-1.4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
