# This script was automatically generated from the dsa-092
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14929);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "092");
 script_cve_id("CVE-2001-1272");
 script_bugtraq_id(3658);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-092 security update');
 script_set_attribute(attribute: 'description', value:
'Nicolas Boullis found a nasty security problem in the wmtv (a
dockable video4linux TV player for windowmaker) package as
distributed in Debian GNU/Linux 2.2.

wmtv can optionally run a command if you double-click on the TV
window. This command can be specified using the -e command line
option. However, since wmtv is installed suid root, this command
was also run as root, which gives local users a very simple way
to get root access.

This has been fixed in version 0.6.5-2potato1 by dropping root
privileges before executing the command. We recommend that you
upgrade your wmtv package immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-092');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-092
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA092] DSA-092-1 wmtv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-092-1 wmtv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wmtv', release: '2.2', reference: '0.6.5-2potato1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
