# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-27.xml
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
 script_id(31614);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-27");
 script_cve_id("CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-27
(MoinMoin: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered:
    A vulnerability exists in the file wikimacro.py because the
    _macro_Getval function does not properly enforce ACLs
    (CVE-2008-1099).
    A directory traversal vulnerability exists in the userform action
    (CVE-2008-0782).
    A Cross-Site Scripting vulnerability exists in the login action
    (CVE-2008-0780).
    Multiple Cross-Site Scripting vulnerabilities exist in the file
    action/AttachFile.py when using the message, pagename, and target
    filenames (CVE-2008-0781).
    Multiple Cross-Site Scripting vulnerabilities exist in
    formatter/text_gedit.py (aka the gui editor formatter) which can be
    exploited via a page name or destination page name, which trigger an
    injection in the file PageEditor.py (CVE-2008-1098).
  
Impact

    These vulnerabilities can be exploited to allow remote attackers to
    inject arbitrary web script or HTML, overwrite arbitrary files, or read
    protected pages.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MoinMoin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/moinmoin-1.6.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0780');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0781');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0782');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1098');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1099');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-27] MoinMoin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MoinMoin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/moinmoin", unaffected: make_list("ge 1.6.1"), vulnerable: make_list("lt 1.6.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
