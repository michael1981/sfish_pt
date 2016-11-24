# This script was automatically generated from the dsa-1560
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32084);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1560");
 script_cve_id("CVE-2008-1974");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1560 security update');
 script_set_attribute(attribute: 'description', value:
'"The-0utl4w" discovered that the Kronolith, calendar component for
the Horde Framework, didn\'t properly sanitise URL input, leading to
a cross-site scripting vulnerability in the add event screen.
For the stable distribution (etch), this problem has been fixed in version
2.1.4-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1560');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kronolith2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1560] DSA-1560-1 kronolith2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1560-1 kronolith2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kronolith2', release: '4.0', reference: '2.1.4-1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
