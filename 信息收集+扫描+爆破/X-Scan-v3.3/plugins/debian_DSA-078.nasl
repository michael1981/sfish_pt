# This script was automatically generated from the dsa-078
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14915);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "078");
 script_cve_id("CVE-2001-1035");
 script_bugtraq_id(3364);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-078 security update');
 script_set_attribute(attribute: 'description', value:
'Byrial Jensen found a nasty problem in slrn (a threaded news reader).
The notice on slrn-announce describes it as follows:



    When trying to decode binaries, the built-in code executes any shell
    scripts the article might contain, apparently assuming they would be
    some kind of self-extracting archive.

This problem has been fixed in version 0.9.6.2-9potato2 by removing
this feature. 

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-078');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-078
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA078] DSA-078-1 slrn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-078-1 slrn");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'slrn', release: '2.2', reference: '0.9.6.2-9potato2');
deb_check(prefix: 'slrnpull', release: '2.2', reference: '0.9.6.2-9potato2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
