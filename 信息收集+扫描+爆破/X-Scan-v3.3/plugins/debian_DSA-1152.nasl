# This script was automatically generated from the dsa-1152
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22694);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1152");
 script_cve_id("CVE-2006-3695");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1152 security update');
 script_set_attribute(attribute: 'description', value:
'Felix Wiemann discovered that trac, an enhanced Wiki and issue
tracking system for software development projects, can be used to
disclose arbitrary local files.  To fix this problem, python-docutils
needs to be updated as well.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1-3sarge5 of trac and version 0.3.7-2sarge1 of
python-docutils.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1152');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your trac and python-docutils packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1152] DSA-1152-1 trac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1152-1 trac");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-docutils', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python-roman', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python2.1-difflib', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python2.1-textwrap', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python2.2-docutils', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python2.2-textwrap', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python2.3-docutils', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'python2.4-docutils', release: '3.1', reference: '0.3.7-2sarge1');
deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
