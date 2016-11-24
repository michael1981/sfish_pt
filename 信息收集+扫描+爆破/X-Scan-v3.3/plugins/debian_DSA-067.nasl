# This script was automatically generated from the dsa-067
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");
if (description)
{
 script_id(14904);
 script_version("$Revision: 1.14 $");
 script_xref(name: "DSA", value: "067");
 script_bugtraq_id(2503);

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the DSA-067 security update." );
 script_set_attribute(attribute:"description", value:
'We have received reports that the `apache\' package, as included in
the Debian `stable\' distribution, is vulnerable to an `artificially
long slash path directory listing vulnerability\'.

This vulnerability was announced to bugtraq by Dan Harkless.

Quoting the SecurityFocus entry for this vulnerability:


 A problem in the package could allow directory indexing, and path
 discovery. In a default configuration, Apache enables mod_dir,
 mod_autoindex, and mod_negotiation. However, by placing a custom
 crafted request to the Apache server consisting of a long path name
 created artificially by using numerous slashes, this can cause these
 modules to misbehave, making it possible to escape the error page,
 and gain a listing of the directory contents.

 This vulnerability makes it possible for a malicious remote user
 to launch an information gathering attack, which could potentially
 result in compromise of the system. Additionally, this vulnerability
 affects all releases of Apache previous to 1.3.19.


This problem has been fixed in apache-ssl 1.3.9-13.3 and
apache 1.3.9-14.  We recommend that you upgrade your packages
immediately.
Warning: The MD5Sum of the .dsc and .diff.gz file don\'t match
since they were copied from the stable release afterwards, the
content of the .diff.gz file is the same, though, checked.');
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-067");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-067 
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_end_attributes();
 
 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA067] DSA-067-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2001-0925");
 script_summary(english: "DSA-067-1 apache");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'apache', release: '2.2', reference: '1.3.9-14');
deb_check(prefix: 'apache-common', release: '2.2', reference: '1.3.9-14');
deb_check(prefix: 'apache-dev', release: '2.2', reference: '1.3.9-14');
deb_check(prefix: 'apache-doc', release: '2.2', reference: '1.3.9-14');
deb_check(prefix: 'apache-ssl', release: '2.2', reference: '1.3.9.13-3');
if (deb_report_get()) security_warning(port: 0, extra: deb_report_get());
