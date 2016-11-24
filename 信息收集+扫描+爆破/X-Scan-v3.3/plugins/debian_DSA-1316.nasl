# This script was automatically generated from the dsa-1316
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25582);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1316");
 script_cve_id("CVE-2007-2833");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1316 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that emacs, the GNU Emacs editor, will crash when
processing certain types of images.
For the stable distribution (etch), this problem has been fixed in version 21.4a+1-3etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1316');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your emacs21 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1316] DSA-1316-1 emacs21");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1316-1 emacs21");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'emacs', release: '4.0', reference: '21.4a+1-3etch1');
deb_check(prefix: 'emacs21', release: '4.0', reference: '21.4a+1-3etch1');
deb_check(prefix: 'emacs21-bin-common', release: '4.0', reference: '21.4a+1-3etch1');
deb_check(prefix: 'emacs21-common', release: '4.0', reference: '21.4a+1-3etch1');
deb_check(prefix: 'emacs21-el', release: '4.0', reference: '21.4a+1-3etch1');
deb_check(prefix: 'emacs21-nox', release: '4.0', reference: '21.4a+1-3etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
