# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-21.xml
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
 script_id(20265);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-21");
 script_cve_id("CVE-2005-2628");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-21
(Macromedia Flash Player: Remote arbitrary code execution)


    When handling a SWF file, the Macromedia Flash Player incorrectly
    validates the frame type identifier stored in the SWF file which is
    used as an index to reference an array of function pointers. A
    specially crafted SWF file can cause this index to reference memory
    outside of the scope of the Macromedia Flash Player, which in turn can
    cause the Macromedia Flash Player to use unintended memory address(es)
    as function pointers.
  
Impact

    An attacker serving a maliciously crafted SWF file could entice a
    user to view the SWF file and execute arbitrary code on the user\'s
    machine.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Macromedia Flash Player users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-plugins/adobe-flash-7.0.61"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2628');
script_set_attribute(attribute: 'see_also', value: 'http://www.macromedia.com/devnet/security/security_zone/mpsb05-07.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-21] Macromedia Flash Player: Remote arbitrary code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Macromedia Flash Player: Remote arbitrary code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-plugins/adobe-flash", unaffected: make_list("ge 7.0.61"), vulnerable: make_list("lt 7.0.61")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
