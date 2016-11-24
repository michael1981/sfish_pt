# This script was automatically generated from the dsa-811
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19690);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "811");
 script_cve_id("CVE-2005-2657");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-811 security update');
 script_set_attribute(attribute: 'description', value:
'The bugfix for the problem mentioned below contained an error that
caused third party programs to fail.  The problem is corrected by this
update.  For completeness we\'re including the original advisory
text:
François-René Rideau discovered a bug in common-lisp-controller, a
Common Lisp source and compiler manager, that allows a local user to
compile malicious code into a cache directory which is executed by
another user if that user has not used Common Lisp before.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.15sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-811');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your common-lisp-controller package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA811] DSA-811-2 common-lisp-controller");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-811-2 common-lisp-controller");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'common-lisp-controller', release: '3.1', reference: '4.15sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
