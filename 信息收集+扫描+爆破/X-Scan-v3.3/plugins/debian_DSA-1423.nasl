# This script was automatically generated from the dsa-1423
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29258);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1423");
 script_cve_id("CVE-2007-5491", "CVE-2007-5492", "CVE-2007-5692", "CVE-2007-5693", "CVE-2007-5694", "CVE-2007-5695");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1423 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in sitebar, a
web based bookmark manager written in PHP.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-5491
   A directory traversal vulnerability in the translation module allows
   remote authenticated users to chmod arbitrary files to 0777 via <q>..</q>
   sequences in the <q>lang</q> parameter.
CVE-2007-5492
   A static code injection vulnerability in the translation module allows
   a remote authenticated user to execute arbitrary PHP code via the <q>value</q>
   parameter.
CVE-2007-5693
   An eval injection vulnerability in the translation module allows 
   remote authenticated users to execute arbitrary PHP code via the
   <q>edit</q> parameter in an <q>upd cmd</q> action.
CVE-2007-5694
   A path traversal vulnerability in the translation module allows 
   remote authenticated users to read arbitrary files via an absolute
   path in the <q>dir</q> parameter.
CVE-2007-5695
   An error in command.php allows remote attackers to redirect users
   to arbitrary web sites via the <q>forward</q> parameter in a <q>Log In</q> action.
CVE-2007-5692
   Multiple cross site scripting flaws allow remote attackers to inject
   arbitrary script or HTML fragments into several scripts.
For the old stable distribution (sarge), these problems have been fixed in
version 3.2.6-7.1sarge1.
For the stable distribution (etch), these problems have been fixed in version
3.3.8-7etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1423');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sitebar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1423] DSA-1423-1 sitebar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1423-1 sitebar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sitebar', release: '3.1', reference: '3.2.6-7.1sarge1');
deb_check(prefix: 'sitebar', release: '4.0', reference: '3.3.8-7etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
