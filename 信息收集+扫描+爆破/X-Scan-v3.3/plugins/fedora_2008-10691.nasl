
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10691
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35227);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-10691: openvpn");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10691 (openvpn)");
 script_set_attribute(attribute: "description", value: "OpenVPN is a robust and highly flexible tunneling application that uses all
of the encryption, authentication, and certification features of the
OpenSSL library to securely tunnel IP networks over a single UDP or TCP
port.  It can use the Marcus Franz Xaver Johannes Oberhumer's LZO library
for compression.

-
Update Information:

2008.11.19 -- Version 2.1_rc15    * Fixed issue introduced in 2.1_rc14 that may
cause a    segfault when a --plugin module is used.    * Added server-side
--opt-verify option: clients that connect    with options that are incompatible
with those of the server    will be disconnected (without this option,
incompatible    clients would trigger a warning message in the server log    bu
t
would not be disconnected).    * Added --tcp-nodelay option: Macro that sets
TCP_NODELAY socket    flag on the server as well as pushes it to connecting
clients.    * Minor options check fix: --no-name-remapping is a    server-only
option and should therefore generate an    error when used on the client.    *
Added --prng option to control PRNG (pseudo-random    number generator)
parameters.  In previous OpenVPN    versions, the PRNG was hardcoded to use the
SHA1    hash.  Now any OpenSSL hash may be used.  This is    part of an effort
to remove hardcoded references to    a specific cipher or cryptographic hash
algorithm.    * Cleaned up man page synopsis.    2008.11.16 -- Version 2.1_rc14

Update information :

* Added AC_GNU_SOURCE to configure.ac to enable struct ucred,    with the goal
of fixing a build issue on Fedora 9 that was    introduced in 2.1_rc13.    *
Added additional method parameter to --script-security to preserve    backward
compatibility with system() call semantics used in OpenVPN    2.1_rc8 and
earlier.  To preserve backward compatibility use:        script-security 3
system    * Added additional warning messages about --script-security 2    or
higher being required to execute user-defined scripts or    executables.    *
Windows build system changes:      Modified Windows domake-win build system to
write all openvpn.nsi    input files to gen, so that gen can be disconnected
from    the rest of the source tree and makensis openvpn.nsi will    still
function correctly.      Added additional SAMPCONF_(CA|CRT|KEY) macros to
settings.in    (commented out by default).      Added optional files
SAMPCONF_CONF2 (second sample configuration    file) and SAMPCONF_DH (Diffie-
Helman parameters) to Windows    build system, and may be defined in
settings.in.    * Extended Management Interface 'bytecount' command    to work
when OpenVPN is running as a server.    Documented Management Interface
'bytecount' command in    management/management-notes.txt.    * Fixed
informational message in ssl.c to properly indicate    deferred authentication.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the openvpn package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"openvpn-2.1-0.29.rc15.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
