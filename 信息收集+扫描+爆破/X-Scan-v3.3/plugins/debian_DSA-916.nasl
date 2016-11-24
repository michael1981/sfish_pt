# This script was automatically generated from the dsa-916
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22782);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "916");
 script_cve_id("CVE-2005-3737", "CVE-2005-3885");
 script_bugtraq_id(14522);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-916 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Inkscape, a
vector-based drawing program.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2005-3737
    Joxean Koret discovered a buffer overflow in the SVG parsing
    routines that can lead to the execution of arbitrary code.
CVE-2005-3885
    Javier Fernández-Sanguino Peña noticed that the ps2epsi extension
    shell script uses a hardcoded temporary file making it vulnerable
    to symlink attacks.
The old stable distribution (woody) does not contain inkscape packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.41-4.99.sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-916');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your inkscape package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA916] DSA-916-1 inkscape");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-916-1 inkscape");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'inkscape', release: '3.1', reference: '0.41-4.99.sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
