# This script was automatically generated from the dsa-097
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14934);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "097");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-097 security update');
 script_set_attribute(attribute: 'description', value:
'Patrice Fournier discovered a bug in all versions of Exim older than
Exim 3.34 and Exim 3.952.
The Exim maintainer, Philip Hazel,
writes about this issue: "The
problem exists only in the case of a run time configuration which
directs or routes an address to a pipe transport without checking the
local part of the address in any way.  This does not apply, for
example, to pipes run from alias or forward files, because the local
part is checked to ensure that it is the name of an alias or of a
local user.  The bug\'s effect is that, instead of obeying the correct
pipe command, a broken Exim runs the command encoded in the local part
of the address."
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-097');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your exim
package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA097] DSA-097-1 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-097-1 exim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exim', release: '2.2', reference: '3.12-10.2');
deb_check(prefix: 'eximon', release: '2.2', reference: '3.12-10.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
