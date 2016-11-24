# This script was automatically generated from the dsa-122
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14959);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "122");
 script_cve_id("CVE-2002-0059");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-122 security update');
 script_set_attribute(attribute: 'description', value:
'The compression library zlib has a flaw in which it attempts to free
memory more than once under certain conditions. This can possibly be
exploited to run arbitrary code in a program that includes zlib. If a
network application running as root is linked to zlib, this could
potentially lead to a remote root compromise. No exploits are known at
this time. This vulnerability is assigned the CVE candidate name of
CVE-2002-0059.
The zlib vulnerability is fixed in the Debian zlib package version
1.1.3-5.1. A number of programs either link statically to zlib or include
a private copy of zlib code. These programs must also be upgraded
to eliminate the zlib vulnerability. The affected packages and fixed
versions follow:
Those using the pre-release (testing) version of Debian should upgrade
to zlib 1.1.3-19.1 or a later version. Note that since this version of
Debian has not yet been released it may not be available immediately for
all architectures. Debian 2.2 (potato) is the latest supported release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-122');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA122] DSA-122-1 zlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-122-1 zlib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'amaya', release: '2.2', reference: '2.4-1potato1');
deb_check(prefix: 'dict', release: '2.2', reference: '1.4.9-9potato1');
deb_check(prefix: 'dictd', release: '2.2', reference: '1.4.9-9potato1');
deb_check(prefix: 'erlang', release: '2.2', reference: '49.1-10.1');
deb_check(prefix: 'erlang-base', release: '2.2', reference: '49.1-10.1');
deb_check(prefix: 'erlang-erl', release: '2.2', reference: '49.1-10.1');
deb_check(prefix: 'erlang-java', release: '2.2', reference: '49.1-10.1');
deb_check(prefix: 'freeamp', release: '2.2', reference: '2.0.6-2.1');
deb_check(prefix: 'freeamp-doc', release: '2.2', reference: '2.0.6-2.1');
deb_check(prefix: 'libfreeamp-alsa', release: '2.2', reference: '2.0.6-2.1');
deb_check(prefix: 'libfreeamp-esound', release: '2.2', reference: '2.0.6-2.1');
deb_check(prefix: 'mirrordir', release: '2.2', reference: '0.10.48-2.1');
deb_check(prefix: 'ppp', release: '2.2', reference: '2.3.11-1.5');
deb_check(prefix: 'rsync', release: '2.2', reference: '2.3.2-1.6');
deb_check(prefix: 'vrweb', release: '2.2', reference: '1.5-5.1');
deb_check(prefix: 'zlib-bin', release: '2.2', reference: '1.1.3-5.1');
deb_check(prefix: 'zlib1', release: '2.2', reference: '1.1.3-5.1');
deb_check(prefix: 'zlib1-altdev', release: '2.2', reference: '1.1.3-5.1');
deb_check(prefix: 'zlib1g', release: '2.2', reference: '1.1.3-5.1');
deb_check(prefix: 'zlib1g-dev', release: '2.2', reference: '1.1.3-5.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
