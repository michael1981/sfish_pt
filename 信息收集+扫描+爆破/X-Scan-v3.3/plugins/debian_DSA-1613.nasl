# This script was automatically generated from the dsa-1613
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33552);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1613");
 script_cve_id("CVE-2007-2445", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3996");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1613 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been identified in libgd2, a library
for programmatic graphics creation and manipulation.  The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-2445
    Grayscale PNG files containing invalid tRNS chunk CRC values
    could cause a denial of service (crash), if a maliciously
    crafted image is loaded into an application using libgd.
CVE-2007-3476
    An array indexing error in libgd\'s GIF handling could induce a
    denial of service (crash with heap corruption) if exceptionally
    large color index values are supplied in a maliciously crafted
    GIF image file.
CVE-2007-3477
    The imagearc() and imagefilledarc() routines in libgd allow
    an attacker in control of the parameters used to specify
    the degrees of arc for those drawing functions to perform
    a denial of service attack (excessive CPU consumption).
CVE-2007-3996
    Multiple integer overflows exist in libgd\'s image resizing and
    creation routines; these weaknesses allow an attacker in control
    of the parameters passed to those routines to induce a crash or
    execute arbitrary code with the privileges of the user running
    an application or interpreter linked against libgd2.
For the stable distribution (etch), these problems have been fixed in
version 2.0.33-5.2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1613');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libgd2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1613] DSA-1613-1 libgd2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1613-1 libgd2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libgd-tools', release: '4.0', reference: '2.0.33-5.2etch1');
deb_check(prefix: 'libgd2-noxpm', release: '4.0', reference: '2.0.33-5.2etch1');
deb_check(prefix: 'libgd2-noxpm-dev', release: '4.0', reference: '2.0.33-5.2etch1');
deb_check(prefix: 'libgd2-xpm', release: '4.0', reference: '2.0.33-5.2etch1');
deb_check(prefix: 'libgd2-xpm-dev', release: '4.0', reference: '2.0.33-5.2etch1');
deb_check(prefix: 'libgd2', release: '4.0', reference: '2.0.33-5.2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
