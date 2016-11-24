# This script was automatically generated from the dsa-263
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15100);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "263");
 script_cve_id("CVE-2003-0146");
 script_xref(name: "CERT", value: "378049");
 script_xref(name: "CERT", value: "630433");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-263 security update');
 script_set_attribute(attribute: 'description', value:
'Al Viro and Alan Cox discovered several maths overflow errors in
NetPBM, a set of graphics conversion tools.  These programs are not
installed setuid root but are often installed to prepare data for
processing.  These vulnerabilities may allow remote attackers to cause
a denial of service or execute arbitrary code.
For the stable distribution (woody) this problem has been
fixed in version 9.20-8.2.
The old stable distribution (potato) does not seem to be affected
by this problem.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-263');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your netpbm package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA263] DSA-263-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-263-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.2');
deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.2');
deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.2');
deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
