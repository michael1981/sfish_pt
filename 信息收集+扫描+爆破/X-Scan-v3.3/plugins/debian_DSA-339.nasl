# This script was automatically generated from the dsa-339
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15176);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "339");
 script_cve_id("CVE-2003-0440");
 script_bugtraq_id(8115);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-339 security update');
 script_set_attribute(attribute: 'description', value:
'NOTE: due to a combination of administrative problems, this advisory
was erroneously released with the identifier "DSA-337-1".  DSA-337-1
correctly refers to an earlier advisory regarding gtksee.
semi, a MIME library for GNU Emacs, does not take appropriate
security precautions when creating temporary files.  This bug could
potentially be exploited to overwrite arbitrary files with the
privileges of the user running Emacs and semi, potentially with
contents supplied by the attacker.
wemi is a fork of semi, and contains the same bug.
For the stable distribution (woody) this problem has been fixed in
semi version 1.14.3.cvs.2001.08.10-1woody2 and wemi version
1.14.0.20010802wemiko-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-339');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-339
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA339] DSA-339-1 semi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-339-1 semi");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'semi', release: '3.0', reference: '1.14.3.cvs.2001.08.10-1woody2');
deb_check(prefix: 'wemi', release: '3.0', reference: '1.14.0.20010802wemiko-1.3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
