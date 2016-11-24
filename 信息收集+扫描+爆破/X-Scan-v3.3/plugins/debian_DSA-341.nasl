# This script was automatically generated from the dsa-341
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15178);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "341");
 script_cve_id("CVE-2003-0537");
 script_bugtraq_id(8124);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-341 security update');
 script_set_attribute(attribute: 'description', value:
'liece, an IRC client for Emacs, does not take appropriate security
precautions when creating temporary files.  This bug could potentially
be exploited to overwrite arbitrary files with the privileges of the
user running Emacs and liece, potentially with contents supplied
by the attacker.
For the stable distribution (woody) this problem has been fixed in
version 2.0+0.20020217cvs-2.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-341');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-341
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA341] DSA-341-1 liece");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-341-1 liece");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'liece', release: '3.0', reference: '2.0+0.20020217cvs-2.1');
deb_check(prefix: 'liece-dcc', release: '3.0', reference: '2.0+0.20020217cvs-2.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
