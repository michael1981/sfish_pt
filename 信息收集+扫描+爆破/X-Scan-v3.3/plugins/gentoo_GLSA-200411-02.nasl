# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-02.xml
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
 script_id(15590);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200411-02");
 script_cve_id("CVE-2004-1097");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-02
(Cherokee: Format string vulnerability)


    Florian Schilhabel from the Gentoo Linux Security Audit Team found a
    format string vulnerability in the cherokee_logger_ncsa_write_string()
    function.
  
Impact

    Using a specially crafted URL when authenticating via auth_pam, a
    malicious user may be able to crash the server or execute arbitrary
    code on the target machine with permissions of the user running
    Cherokee.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cherokee users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/cherokee-0.4.17.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1097');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-02] Cherokee: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cherokee: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/cherokee", unaffected: make_list("ge 0.4.17.1"), vulnerable: make_list("le 0.4.17")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
