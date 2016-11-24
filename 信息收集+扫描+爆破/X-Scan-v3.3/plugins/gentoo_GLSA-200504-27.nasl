# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-27.xml
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
 script_id(18145);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-27");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-27
(xine-lib: Two heap overflow vulnerabilities)


    Heap overflows have been found in the code handling RealMedia RTSP
    and Microsoft Media Services streams over TCP (MMST).
  
Impact

    By setting up a malicious server and enticing a user to use its
    streaming data, a remote attacker could possibly execute arbitrary code
    on the client computer with the permissions of the user running any
    multimedia frontend making use of the xine-lib library.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/xine-lib
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://xinehq.de/index.php/security/XSA-2004-8');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-27] xine-lib: Two heap overflow vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Two heap overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1.0-r2", "rge 1_rc6-r2"), vulnerable: make_list("lt 1.0-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
