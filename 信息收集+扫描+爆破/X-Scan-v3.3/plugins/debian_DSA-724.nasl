# This script was automatically generated from the dsa-724
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18303);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "724");
 script_cve_id("CVE-2005-0870");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-724 security update');
 script_set_attribute(attribute: 'description', value:
'Maksymilian Arciemowicz discovered several cross site scripting issues
in phpsysinfo, a PHP based host information application.
For the stable distribution (woody) these problems have been fixed in
version 2.0-3woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-724');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpsysinfo package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA724] DSA-724-1 phpsysinfo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-724-1 phpsysinfo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
