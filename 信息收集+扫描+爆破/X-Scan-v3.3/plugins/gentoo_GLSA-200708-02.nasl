# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-02.xml
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
 script_id(25867);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200708-02");
 script_cve_id("CVE-2007-3329");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-02
(Xvid: Array indexing vulnerabilities)


    Trixter Jack discovered an array indexing error in the
    get_intra_block() function in the file src/bitstream/mbcoding.c. The
    get_inter_block_h263() and get_inter_block_mpeg() functions in the same
    file were also reported as vulnerable.
  
Impact

    An attacker could exploit these vulnerabilities to execute arbitrary
    code by tricking a user or automated system into processing a malicious
    video file with an application that makes use of the Xvid library.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xvid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/xvid-1.1.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3329');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-02] Xvid: Array indexing vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xvid: Array indexing vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xvid", unaffected: make_list("ge 1.1.3"), vulnerable: make_list("lt 1.1.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
