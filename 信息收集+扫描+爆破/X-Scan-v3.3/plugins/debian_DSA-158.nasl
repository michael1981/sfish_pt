# This script was automatically generated from the dsa-158
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14995);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "158");
 script_cve_id("CVE-2002-0989");
 script_bugtraq_id(5574);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-158 security update');
 script_set_attribute(attribute: 'description', value:
'The developers of Gaim, an instant messenger client that combines
several different networks, found a vulnerability in the hyperlink
handling code.  The \'Manual\' browser command passes an untrusted
string to the shell without escaping or reliable quoting, permitting
an attacker to execute arbitrary commands on the users machine.
Unfortunately, Gaim doesn\'t display the hyperlink before the user
clicks on it.  Users who use other inbuilt browser commands aren\'t
vulnerable.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-158');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gaim package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA158] DSA-158-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-158-1 gaim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gaim', release: '3.0', reference: '0.58-2.2');
deb_check(prefix: 'gaim-common', release: '3.0', reference: '0.58-2.2');
deb_check(prefix: 'gaim-gnome', release: '3.0', reference: '0.58-2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
