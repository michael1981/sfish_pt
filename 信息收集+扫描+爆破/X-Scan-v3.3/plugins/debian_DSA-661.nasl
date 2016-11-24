# This script was automatically generated from the dsa-661
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16266);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "661");
 script_cve_id("CVE-2005-0017", "CVE-2005-0018");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-661 security update');
 script_set_attribute(attribute: 'description', value:
'Dan McMahill noticed that our advisory DSA 661-1 did not correct
the multiple insecure files problem, hence, this update. For
completeness below is the original advisory text:
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that f2c and fc, which are both part of the f2c package, a
fortran 77 to C/C++ translator, open temporary files insecurely and
are hence vulnerable to a symlink attack.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Multiple insecure temporary files in the f2c translator.
    Two insecure temporary files in the f2 shell script.
For the stable distribution (woody) and all others including testing
this problem has been fixed in version 20010821-3.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-661');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your f2c package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA661] DSA-661-2 f2c");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-661-2 f2c");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'f2c', release: '3.0', reference: '20010821-3.2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
