# This script was automatically generated from the dsa-448
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15285);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "448");
 script_cve_id("CVE-2004-0097");
 script_bugtraq_id(9406);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-448 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities were discovered in pwlib, a library used to
aid in writing portable applications, whereby a remote attacker could
cause a denial of service or potentially execute arbitrary code.  This
library is most notably used in several applications implementing the
H.323 teleconferencing protocol, including the OpenH323 suite,
gnomemeeting and asterisk.
For the current stable distribution (woody) this problem has been
fixed in version 1.2.5-5woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-448');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-448
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA448] DSA-448-1 pwlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-448-1 pwlib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'asnparser', release: '3.0', reference: '1.2.5-5woody1');
deb_check(prefix: 'libpt-1.2.0', release: '3.0', reference: '1.2.5-5woody1');
deb_check(prefix: 'libpt-dbg', release: '3.0', reference: '1.2.5-5woody1');
deb_check(prefix: 'libpt-dev', release: '3.0', reference: '1.2.5-5woody1');
deb_check(prefix: 'pwlib', release: '3.0', reference: '1.2.5-5woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
