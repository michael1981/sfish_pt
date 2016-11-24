# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-22.xml
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
 script_id(22284);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200608-22");
 script_cve_id("CVE-2006-3119");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-22
(fbida: Arbitrary command execution)


    Toth Andras has discovered a typographic mistake in the "fbgs" script,
    shipped with fbida if the "fbcon" and "pdf" USE flags are both enabled.
    This script runs "gs" without the -dSAFER option, thus allowing a
    PostScript file to execute, delete or create any kind of file on the
    system.
  
Impact

    A remote attacker can entice a vulnerable user to view a malicious
    PostScript or PDF file with fbgs, which may result with the execution
    of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All fbida users with the "fbcon" and "pdf" USE flags both enabled
    should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/fbida-2.03-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3119');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-22] fbida: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'fbida: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/fbida", unaffected: make_list("ge 2.03-r4"), vulnerable: make_list("lt 2.03-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
