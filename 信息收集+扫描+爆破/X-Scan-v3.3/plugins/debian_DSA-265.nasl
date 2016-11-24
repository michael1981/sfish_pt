# This script was automatically generated from the dsa-265
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15102);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "265");
 script_cve_id("CVE-2003-0152", "CVE-2003-0153", "CVE-2003-0154", "CVE-2003-0155");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-265 security update');
 script_set_attribute(attribute: 'description', value:
'Rémi Perrot fixed several security related bugs in the bonsai, the
Mozilla CVS query tool by web interface.  Vulnerabilities include
arbitrary code execution, cross-site scripting and access to
configuration parameters.  The Common Vulnerabilities and Exposures
project identifies the following problems:
For the stable distribution (woody) these problems have been fixed in
version 1.3+cvs20020224-1woody1.
The old stable distribution (potato) is not affected since it doesn\'t
contain bonsai.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-265');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bonsai package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA265] DSA-265-1 bonsai");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-265-1 bonsai");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bonsai', release: '3.0', reference: '1.3+cvs20020224-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
