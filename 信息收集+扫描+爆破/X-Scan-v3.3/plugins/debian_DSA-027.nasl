# This script was automatically generated from the dsa-027
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14864);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "027");
 script_cve_id("CVE-2001-0361");
 script_bugtraq_id(2344);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-027 security update');
 script_set_attribute(attribute: 'description', value:
'Versions of OpenSSH prior to 2.3.0 are vulnerable to a remote arbitrary
memory overwrite attack which may lead to a root exploit.
CORE-SDI has described a problem with regards to RSA key exchange and a
Bleichenbacher attack to gather the session key from an ssh session. 

Both of these issues have been corrected in our ssh package 1.2.3-9.2.

We recommend you upgrade your openssh package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-027');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-027
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA027] DSA-027-1 OpenSSH");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-027-1 OpenSSH");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh', release: '2.2', reference: '1.2.3-9.2');
deb_check(prefix: 'ssh-askpass-gnome', release: '2.2', reference: '1.2.3-9.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
