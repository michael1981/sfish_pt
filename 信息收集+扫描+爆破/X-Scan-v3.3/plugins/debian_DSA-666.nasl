# This script was automatically generated from the dsa-666
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16340);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "666");
 script_cve_id("CVE-2005-0089");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-666 security update');
 script_set_attribute(attribute: 'description', value:
'The Python development team has discovered a flaw in their language
package.  The SimpleXMLRPCServer library module could permit remote
attackers unintended access to internals of the registered object or
its module or possibly other modules.  The flaw only affects Python
XML-RPC servers that use the register_instance() method to register an
object without a _dispatch() method.  Servers using only
register_function() are not affected.
For the stable distribution (woody) this problem has been fixed in
version 2.2.1-4.7.  No other version of Python in woody is affected.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-666');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Python packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA666] DSA-666-1 python2.2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-666-1 python2.2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle-python2.2', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-dev', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-doc', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-elisp', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-examples', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-gdbm', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-mpz', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-tk', release: '3.0', reference: '2.2.1-4.7');
deb_check(prefix: 'python2.2-xmlbase', release: '3.0', reference: '2.2.1-4.7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
