# This script was automatically generated from the dsa-188
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15025);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "188");
 script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
 script_bugtraq_id(5847, 5884, 5887, 5995);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-188 security update');
 script_set_attribute(attribute: 'description', value:
'According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several vulnerabilities have been found in the Apache
package, a commonly used webserver.  Most of the code is shared
between the Apache and Apache-SSL packages, so vulnerabilities are
shared as well.  These vulnerabilities could allow an attacker to
enact a denial of service against a server or execute a cross
scripting attack, or steal cookies from other web site users.
Vulnerabilities in the included legacy programs htdigest, htpasswd and
ApacheBench can be exploited when called via CGI.  Additionally the
insecure temporary file creation in htdigest and htpasswd can also be
exploited locally.  The Common Vulnerabilities and Exposures (CVE)
project identified the following vulnerabilities:
   This is the same vulnerability as CVE-2002-1233, which was fixed in
   potato already but got lost later and was never applied upstream.
   (binaries not included in apache-ssl package though)
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-188');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Apache-SSL package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA188] DSA-188-1 apache-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-188-1 apache-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache-ssl', release: '2.2', reference: '1.3.9.13-4.2');
deb_check(prefix: 'apache-ssl', release: '3.0', reference: '1.3.26.1+1.48-0woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
