# This script was automatically generated from the dsa-1390
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27545);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1390");
 script_cve_id("CVE-2007-4033");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1390 security update');
 script_set_attribute(attribute: 'description', value:
'Hamid Ebadi discovered a buffer overflow in the
intT1_Env_GetCompletePath routine in t1lib, a Type 1 font rasterizer
library.  This flaw could allow an attacker to crash an application
using the t1lib shared libraries, and potentially execute arbitrary code
within such an application\'s security context.
For the old stable distribution (sarge), this problem has been fixed in
version 5.0.2-3sarge1.
For the stable distribution (etch), this problem has been fixed in
version 5.1.0-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1390');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your t1lib package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1390] DSA-1390-1 t1lib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1390-1 t1lib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libt1-5', release: '3.1', reference: '5.0.2-3sarge1');
deb_check(prefix: 'libt1-dev', release: '3.1', reference: '5.0.2-3sarge1');
deb_check(prefix: 'libt1-doc', release: '3.1', reference: '5.0.2-3sarge1');
deb_check(prefix: 't1lib-bin', release: '3.1', reference: '5.0.2-3sarge1');
deb_check(prefix: 'libt1-5', release: '4.0', reference: '5.1.0-2etch1');
deb_check(prefix: 'libt1-dev', release: '4.0', reference: '5.1.0-2etch1');
deb_check(prefix: 'libt1-doc', release: '4.0', reference: '5.1.0-2etch1');
deb_check(prefix: 't1lib-bin', release: '4.0', reference: '5.1.0-2etch1');
deb_check(prefix: 't1lib', release: '4.0', reference: '5.1.0-2etch1');
deb_check(prefix: 't1lib', release: '3.1', reference: '5.0.2-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
