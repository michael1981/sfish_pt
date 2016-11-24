# This script was automatically generated from the dsa-114
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14951);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "114");
 script_cve_id("CVE-2002-0300");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-114 security update');
 script_set_attribute(attribute: 'description', value:
'Thomas Springer found a vulnerability in GNUJSP, a Java servlet that
allows you to insert Java source code into HTML files.  The problem
can be used to bypass access restrictions in the web server.  An
attacker can view the contents of directories and download files
directly rather then receiving their HTML output.  This means that the
source code of scripts could also be revealed.
The problem was fixed by Stefan Gybas, who maintains the Debian
package of GNUJSP.  It is fixed in version 1.0.0-5 for the stable
release of Debian GNU/Linux.
The versions in testing and unstable are the same as the one in stable
so they are vulnerable, too.  You can install the fixed version this
advisory refers to on these systems to solve the problem as this
package is architecture independent.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-114');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnujsp package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA114] DSA-114-1 gnujsp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-114-1 gnujsp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnujsp', release: '2.2', reference: '1.0.0-5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
