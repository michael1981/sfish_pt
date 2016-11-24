# This script was automatically generated from the dsa-525
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15362);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "525");
 script_cve_id("CVE-2004-0492");
 script_bugtraq_id(10508);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-525 security update');
 script_set_attribute(attribute: 'description', value:
'Georgi Guninski discovered a buffer overflow bug in Apache\'s mod_proxy
module, whereby a remote user could potentially cause arbitrary code
to be executed with the privileges of an Apache httpd child process
(by default, user www-data).  Note that this bug is only exploitable
if the mod_proxy module is in use.
Note that this bug exists in a module in the apache-common package,
shared by apache, apache-ssl and apache-perl, so this update is
sufficient to correct the bug for all three builds of Apache httpd.
However, on systems using apache-ssl or apache-perl, httpd will not
automatically be restarted.
For the current stable distribution (woody), this problem has been
fixed in version 1.3.26-0woody5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-525');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-525
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA525] DSA-525-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-525-1 apache");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody5');
deb_check(prefix: 'apache-common', release: '3.0', reference: '1.3.26-0woody5');
deb_check(prefix: 'apache-dev', release: '3.0', reference: '1.3.26-0woody5');
deb_check(prefix: 'apache-doc', release: '3.0', reference: '1.3.26-0woody5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
