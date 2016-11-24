# This script was automatically generated from the dsa-733
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18595);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "733");
 script_cve_id("CVE-2005-0393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-733 security update');
 script_set_attribute(attribute: 'description', value:
'Justin Rye discovered that crip, a terminal-based ripper, encoder and
tagger tool, utilises temporary files in an insecure fashion in its
helper scripts.
The old stable distribution (woody) does not provide the crip package.
For the stable distribution (sarge) this problem has been fixed in
version 3.5-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-733');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your crip package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA733] DSA-733-1 crip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-733-1 crip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'crip', release: '3.1', reference: '3.5-1sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
