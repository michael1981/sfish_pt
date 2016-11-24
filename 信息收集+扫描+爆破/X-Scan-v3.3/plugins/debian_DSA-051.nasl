# This script was automatically generated from the dsa-051
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);


include("compat.inc");

if (description) {
 script_id(14888);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "051");
 script_cve_id("CVE-2001-0596");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the DSA-051 security update." );
 script_set_attribute(attribute:"description", value:
"Florian Wesch has discovered a problem (reported to bugtraq) with the
way how Netscape handles comments in GIF files.  The Netscape browser
does not escape the GIF file comment in the image information page.
This allows javascript execution in the about: protocol and can for
example be used to upload the History (about:global) to a webserver,
thus leaking private information.  This problem has been fixed
upstream in Netscape 4.77.

Since we haven't received source code for these packages, they are not
part of the Debian GNU/Linux distribution, but are packaged up as '.deb'
files for a convenient installation.

We recommend that you upgrade your Netscape packages immediately and
remove older versions." );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-051" );
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-051 
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_copyright(english: "This script is (C) 2008 Tenable Network Security, Inc.");
 script_name(english: "[DSA051] DSA-051-1 netscape");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-051-1 netscape");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'communicator', release: '2.2', reference: '4.77-1');
deb_check(prefix: 'communicator-base-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'communicator-nethelp-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'communicator-smotif-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'communicator-spellchk-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'navigator', release: '2.2', reference: '4.77-1');
deb_check(prefix: 'navigator-base-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'navigator-nethelp-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'navigator-smotif-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'netscape', release: '2.2', reference: '4.77-1');
deb_check(prefix: 'netscape-base-4', release: '2.2', reference: '4.77-1');
deb_check(prefix: 'netscape-base-4-libc5', release: '2.2', reference: '4.77-1');
deb_check(prefix: 'netscape-base-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'netscape-ja-resource-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'netscape-java-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'netscape-ko-resource-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'netscape-smotif-477', release: '2.2', reference: '4.77-2');
deb_check(prefix: 'netscape-zh-resource-477', release: '2.2', reference: '4.77-2');
r = deb_report_get();
if (r) security_hole(port: 0, extra: r);

