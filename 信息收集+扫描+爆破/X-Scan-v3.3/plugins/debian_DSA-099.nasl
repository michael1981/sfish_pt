# This script was automatically generated from the dsa-099
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14936);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "099");
 script_cve_id("CVE-2002-0006");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-099 security update');
 script_set_attribute(attribute: 'description', value:
'zen-parse found a vulnerability in the XChat IRC client that allows an
attacker to take over the users IRC session.
It is possible to trick XChat IRC clients into sending arbitrary
commands to the IRC server they are on, potentially allowing social
engineering attacks, channel takeovers, and denial of service.  This
problem exists in versions 1.4.2 and 1.4.3.  Later versions of XChat
are vulnerable as well, but this behaviour is controlled by the
configuration variable »percascii«, which defaults to 0.  If it is set
to 1 then the problem becomes apparent in 1.6/1.8 as well.
This problem has been fixed in upstream version 1.8.7 and in version
1.4.3-1 for the current stable Debian release (2.2) with a patch
provided from the upstream author Peter Zelezny.  We recommend that
you upgrade your XChat packages immediately, since this problem is
already actively being exploited.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-099');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-099
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA099] DSA-099-1 xchat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-099-1 xchat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xchat', release: '2.2', reference: '1.4.3-1');
deb_check(prefix: 'xchat-common', release: '2.2', reference: '1.4.3-1');
deb_check(prefix: 'xchat-gnome', release: '2.2', reference: '1.4.3-1');
deb_check(prefix: 'xchat-text', release: '2.2', reference: '1.4.3-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
