# This script was automatically generated from the dsa-1131
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22673);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1131");
 script_cve_id("CVE-2006-3747");
 script_xref(name: "CERT", value: "395412");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1131 security update');
 script_set_attribute(attribute: 'description', value:
'Mark Dowd discovered a buffer overflow in the mod_rewrite component of
apache, a versatile high-performance HTTP server.  In some situations a
remote attacker could exploit this to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in version 1.3.33-6sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1131');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apache package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1131] DSA-1131-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1131-1 apache");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-common', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-dbg', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-dev', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-doc', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-perl', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-ssl', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'apache-utils', release: '3.1', reference: '1.3.33-6sarge2');
deb_check(prefix: 'libapache-mod-perl', release: '3.1', reference: '1.29.0.3-6sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
