# This script was automatically generated from the dsa-477
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15314);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "477");
 script_cve_id("CVE-2004-0372");
 script_bugtraq_id(9939, 9939);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-477 security update');
 script_set_attribute(attribute: 'description', value:
'Shaun Colley discovered a problem in xine-ui, the xine video player
user interface.  A script contained in the package to possibly remedy
a problem or report a bug does not create temporary files in a secure
fashion.  This could allow a local attacker to overwrite files with
the privileges of the user invoking xine.
This update also removes the bug reporting facility since bug reports
can\'t be processed upstream anymore.
For the stable distribution (woody) this problem has been fixed in
version 0.9.8-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-477');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xine-ui package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA477] DSA-477-1 xine-ui");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-477-1 xine-ui");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xine-ui', release: '3.0', reference: '0.9.8-5.1');
deb_check(prefix: 'xine-ui', release: '3.0', reference: '0.9.8-5');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
