# This script was automatically generated from the dsa-1021
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22563);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1021");
 script_cve_id("CVE-2005-2471");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1021 security update');
 script_set_attribute(attribute: 'description', value:
'Max Vozeler from the Debian Audit Project discovered that pstopnm, a
converter from Postscript to the PBM, PGM and PNM formats, launches
Ghostscript in an insecure manner, which might lead to the execution
of arbitrary shell commands, when converting specially crafted Postscript
files.
For the old stable distribution (woody) this problem has been fixed in
version 9.20-8.6.
For the stable distribution (sarge) this problem has been fixed in
version 10.0-8sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1021');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your netpbm package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1021] DSA-1021-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1021-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.6');
deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.6');
deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.6');
deb_check(prefix: 'libnetpbm10', release: '3.1', reference: '10.0-8sarge3');
deb_check(prefix: 'libnetpbm10-dev', release: '3.1', reference: '10.0-8sarge3');
deb_check(prefix: 'libnetpbm9', release: '3.1', reference: '10.0-8sarge3');
deb_check(prefix: 'libnetpbm9-dev', release: '3.1', reference: '10.0-8sarge3');
deb_check(prefix: 'netpbm', release: '3.1', reference: '10.0-8sarge3');
deb_check(prefix: 'netpbm-free', release: '3.1', reference: '10.0-8sarge3');
deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
