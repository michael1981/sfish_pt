# This script was automatically generated from the dsa-999
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22865);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "999");
 script_cve_id("CVE-2006-1062", "CVE-2006-1063", "CVE-2006-1064");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-999 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in lurker, an
archive tool for mailing lists with integrated search engine.  The
Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-1062
    Lurker\'s mechanism for specifying configuration files was
    vulnerable to being overridden.  As lurker includes sections of
    unparsed config files in its output, an attacker could manipulate
    lurker into reading any file readable by the www-data user.
CVE-2006-1063
    It is possible for a remote attacker to create or overwrite files
    in any writable directory that is named "mbox".
CVE-2006-1064
    Missing input sanitising allows an attacker to inject arbitrary
    web script or HTML.
The old stable distribution (woody) does not contain lurker packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.2-5sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-999');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lurker package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA999] DSA-999-1 lurker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-999-1 lurker");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lurker', release: '3.1', reference: '1.2-5sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
