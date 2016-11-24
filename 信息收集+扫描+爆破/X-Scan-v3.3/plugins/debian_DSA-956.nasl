# This script was automatically generated from the dsa-956
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22822);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "956");
 script_cve_id("CVE-2006-0353");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-956 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Pfetzing discovered that lshd, a Secure Shell v2 (SSH2)
protocol server, leaks a couple of file descriptors, related to the
randomness generator, to user shells which are started by lshd.  A
local attacker can truncate the server\'s seed file, which may prevent
the server from starting, and with some more effort, maybe also crack
session keys.
After applying this update, you should remove the server\'s seed file
(/var/spool/lsh/yarrow-seed-file) and then regenerate it with
"lsh-make-seed --server" as root.
For security reasons, lsh-make-seed really needs to be run from the
console of the system you are running it on.  If you run lsh-make-seed
using a remote shell, the timing information lsh-make-seed uses for
its random seed creation is likely to be screwed.  If need be, you can
generate the random seed on a different system than that which it will
eventually be on, by installing the lsh-utils package and running
"lsh-make-seed -o my-other-server-seed-file".  You may then transfer
the seed to the destination system as using a secure connection.
The old stable distribution (woody) may not be affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-956');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lsh-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA956] DSA-956-1 lsh-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-956-1 lsh-server");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lsh-client', release: '3.1', reference: '2.0.1-3sarge1');
deb_check(prefix: 'lsh-server', release: '3.1', reference: '2.0.1-3sarge1');
deb_check(prefix: 'lsh-utils', release: '3.1', reference: '2.0.1-3sarge1');
deb_check(prefix: 'lsh-utils-doc', release: '3.1', reference: '2.0.1-3sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
