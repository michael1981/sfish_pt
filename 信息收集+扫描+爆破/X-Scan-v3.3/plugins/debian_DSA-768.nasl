# This script was automatically generated from the dsa-768
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19317);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "768");
 script_cve_id("CVE-2005-2161");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-768 security update');
 script_set_attribute(attribute: 'description', value:
'A cross-site scripting vulnerability has been detected in phpBB2, a
fully featured and skinnable flat webforum software, that allows
remote attackers to inject arbitrary web script or HTML via nested
tags.
The old stable distribution (woody) does not contain phpbb2.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.13-6sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-768');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpbb2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA768] DSA-768-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-768-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge1');
deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge1');
deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
