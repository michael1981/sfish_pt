# This script was automatically generated from the dsa-911
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22777);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "911");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 script_bugtraq_id(15428);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-911 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in gtk+2.0, the Gtk+ GdkPixBuf
XPM image rendering library.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2005-2975
    Ludwig Nussel discovered an infinite loop when processing XPM
    images that allows an attacker to cause a denial of service via a
    specially crafted XPM file.
CVE-2005-2976
    Ludwig Nussel discovered an integer overflow in the way XPM images
    are processed that could lead to the execution of arbitrary code
    or crash the application via a specially crafted XPM file.
CVE-2005-3186
    "infamous41md" discovered an integer overflow in the XPM processing
    routine that can be used to execute arbitrary code via a traditional heap
    overflow.
The following matrix explains which versions fix these problems:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-911');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gtk+2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA911] DSA-911-1 gtk+2.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-911-1 gtk+2.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gtk2.0-examples', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'libgtk-common', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'libgtk2.0-0', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'libgtk2.0-common', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'libgtk2.0-dbg', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'libgtk2.0-dev', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'libgtk2.0-doc', release: '3.0', reference: '2.0.2-5woody3');
deb_check(prefix: 'gtk2-engines-pixbuf', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'gtk2.0-examples', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'libgtk2.0-0', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'libgtk2.0-0-dbg', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'libgtk2.0-bin', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'libgtk2.0-common', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'libgtk2.0-dev', release: '3.1', reference: '2.6.4-3.1');
deb_check(prefix: 'libgtk2.0-doc', release: '3.1', reference: '2.6.4-3.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
