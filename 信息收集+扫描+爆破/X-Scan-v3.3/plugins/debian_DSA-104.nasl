# This script was automatically generated from the dsa-104
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14941);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "104");
 script_cve_id("CVE-2002-0047");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-104 security update');
 script_set_attribute(attribute: 'description', value:
'Larry McVoy found a bug in the packet handling code for the CIPE
VPN package: it did not check if a received packet was too short 
and could crash.
This has been fixed in version 1.3.0-3, and we recommend that you
upgrade your CIPE packages immediately.
Please note that the package only contains the required kernel patch,
you will have to manually build the kernel modules for your kernel with the
updated source from the cipe-source package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-104');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-104
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA104] DSA-104-1 cipe");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-104-1 cipe");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cipe-common', release: '2.2', reference: '1.3.0-3');
deb_check(prefix: 'cipe-source', release: '2.2', reference: '1.3.0-3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
