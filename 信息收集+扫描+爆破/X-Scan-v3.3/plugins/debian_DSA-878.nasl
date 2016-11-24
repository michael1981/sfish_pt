# This script was automatically generated from the dsa-878
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22744);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "878");
 script_cve_id("CVE-2005-2978");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-878 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been identified in the pnmtopng component of the
netpbm package, a set of graphics conversion tools.  This
vulnerability could allow an attacker to execute arbitrary code as a
local user by providing a specially crafted PNM file.
The old stable distribution (woody) it not vulnerable to this problem.
For the stable distribution (sarge) this problem has been fixed in
version 10.0-8sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-878');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your netpbm-free packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA878] DSA-878-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-878-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnetpbm10', release: '3.1', reference: '10.0-8sarge1');
deb_check(prefix: 'libnetpbm10-dev', release: '3.1', reference: '10.0-8sarge1');
deb_check(prefix: 'libnetpbm9', release: '3.1', reference: '10.0-8sarge1');
deb_check(prefix: 'libnetpbm9-dev', release: '3.1', reference: '10.0-8sarge1');
deb_check(prefix: 'netpbm', release: '3.1', reference: '10.0-8sarge1');
deb_check(prefix: 'netpbm-free', release: '3.1', reference: '10.0-8sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
