# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(20953);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200602-11");
 script_cve_id("CVE-2006-0225");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200602-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200602-11
(OpenSSH, Dropbear: Insecure use of system() call)


    To copy from a local filesystem to another local filesystem, scp
    constructs a command line using \'cp\' which is then executed via
    system(). Josh Bressers discovered that special characters are not
    escaped by scp, but are simply passed to the shell.
  
Impact

    By tricking other users or applications to use scp on maliciously
    crafted filenames, a local attacker user can execute arbitrary commands
    with the rights of the user running scp.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSH users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openssh-4.2_p1-r1"
    All Dropbear users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/dropbear-0.47-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0225');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200602-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200602-11] OpenSSH, Dropbear: Insecure use of system() call');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSH, Dropbear: Insecure use of system() call');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/dropbear", unaffected: make_list("ge 0.47-r1"), vulnerable: make_list("lt 0.47-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-misc/openssh", unaffected: make_list("ge 4.2_p1-r1"), vulnerable: make_list("lt 4.2_p1-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
