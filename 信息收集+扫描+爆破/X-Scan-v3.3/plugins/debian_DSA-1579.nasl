# This script was automatically generated from the dsa-1579
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32380);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1579");
 script_cve_id("CVE-2008-0554");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1579 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in the GIF reader implementation in
netpbm-free, a suite of image manipulation utilities.  Insufficient
input data validation could allow a maliciously-crafted GIF file
to overrun a stack buffer, potentially permitting the execution of
arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 2:10.0-11.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1579');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your netpbm packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1579] DSA-1579-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1579-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnetpbm10', release: '4.0', reference: '10.0-11.1+etch1');
deb_check(prefix: 'libnetpbm10-dev', release: '4.0', reference: '10.0-11.1+etch1');
deb_check(prefix: 'libnetpbm9', release: '4.0', reference: '10.0-11.1+etch1');
deb_check(prefix: 'libnetpbm9-dev', release: '4.0', reference: '10.0-11.1+etch1');
deb_check(prefix: 'netpbm', release: '4.0', reference: '10.0-11.1+etch1');
deb_check(prefix: 'netpbm-free', release: '4.0', reference: '10.0-11.1+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
